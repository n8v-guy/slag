# -*- coding: utf-8 -*-
"""scheduler for regular tasks"""
import atexit
import collections
import contextlib
import datetime
import functools
import hashlib
import logging
import os
import time
import threading

import psutil
import rollbar

import callable_ref


LOG = logging.getLogger(__name__)


Env = collections.namedtuple('Env', ['ctx', 'mongo', 'scheduler'])


class RemoveJob(Exception):
    """do not schedule job anymore"""
    pass


class RestartJob(Exception):
    """repeat job immediately"""
    pass


class DeferJob(Exception):
    """retry job after timeout"""
    pass


class ReplaceJob(Exception):
    """replace job function"""
    def __init__(self, func):
        super(ReplaceJob, self).__init__()
        self.func = func


def task_logging(func):
    """Decorator for tasks logging"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        """Logs run progress & exception"""
        LOG.info('scheduler [%s] start, args=(%s)', func.__name__,
                 callable_ref.Callable.printable_params(*args, **kwargs))
        try:
            result = func(*args, **kwargs)
            LOG.info('scheduler [%s] finish, res=%s',
                     func.__name__, repr(result))
            return result
        # reraise *Job exceptions
        except (RemoveJob, RestartJob, DeferJob, ReplaceJob):
            raise
        # pylint: disable=broad-except
        except Exception:
            LOG.exception('scheduler [%s] exception', func.__name__)
            if rollbar._initialized:  # pylint: disable=protected-access
                rollbar.report_exc_info()
            raise RestartJob()
    return wrapper


def run_once_direct(job_func):
    """Run job & cancel it then"""
    job_func()
    raise RemoveJob()


def queue_jobs(env, jobs_list):
    """Runs first job from the list and schedules the rest of list"""
    next_job = jobs_list.pop(0)
    job_func = env.scheduler.serializer.loads(next_job)
    try:
        job_func()
    except (RemoveJob, ReplaceJob):
        assert False, \
            "Raising RemoveJob/ReplaceJob in queued jobs is not allowed"
    # Save the rest of the queue as replacement for the current task
    LOG.info('scheduler: pop queue job ' + next_job)
    queue_tail = functools.partial(queue_jobs, env, jobs_list)
    if jobs_list:
        raise ReplaceJob(queue_tail)


class JobProxy(object):
    """Job with ability to be serialized"""

    JOB_PROPS = {'interval', 'unit', 'at_time', 'last_run', 'next_run',
                 'period', 'start_day', 'exec_once', '_id'}
    JOB_PROPS_DUMPS = {
        'at_time': lambda timestamp: timestamp.isoformat(),
        'period': lambda period: str(int(period.total_seconds())),
    }
    JOB_PROPS_LOADS = {
        'at_time': lambda str_val: datetime.datetime.strptime(
            str_val, '%H:%M:%S').time(),
        'period': lambda str_val: datetime.timedelta(seconds=int(str_val)),
    }

    def __init__(self, job, scheduler):
        self._src_job = job
        self.scheduler = scheduler
        # run ('til return) only once
        self.exec_once = False
        # replace do method to our own
        self.job_do = job.do
        job.do = self.do_wrapped
        setattr(job, 'do_once', self.do_once)
        if not getattr(job, '_id', None):
            self._id = None

    def get_id(self):
        """Try to avoid changing _id member which should be const"""
        return self._id

    def do_wrapped(self, job_func, *args, **kwargs):
        """Proxy to original job"""
        assert self._src_job.job_func is None
        self.job_do(job_func, *args, **kwargs)
        job_func_str = self.scheduler.serializer.dumps(self.job_func)
        self._id = hashlib.md5(job_func_str).hexdigest()
        self.scheduler.serialize_job(self)
        return self

    def do_once(self, job_func, *args, **kwargs):
        """Proxy to original with ability to run ('til return) only once"""
        self.exec_once = True
        return self.do_wrapped(job_func, *args, **kwargs)

    def __getattr__(self, *args):
        """all methods binding"""
        return getattr(self._src_job, args[0])

    def __repr__(self):
        """Serializes job's callable"""
        return self.scheduler.serializer.dumps(self.job_func)

    @staticmethod
    def from_dict(job, scheduler, job_dict):
        """Init job fields from db data"""
        job_func = scheduler.serializer.loads(job_dict['job_func'])
        for prop in job_dict.keys():
            if job_dict[prop] and prop in JobProxy.JOB_PROPS_LOADS:
                loads = JobProxy.JOB_PROPS_LOADS[prop]
                setattr(job, prop, loads(job_dict[prop]))
            else:
                setattr(job, prop, job_dict[prop])
        # schedule lib internal requirement
        job.do(job_func)
        return JobProxy(job, scheduler)

    def to_dict(self):
        """:returns dict with all attributes"""
        props = {'job_func': self.scheduler.serializer.dumps(self.job_func)}
        for prop in JobProxy.JOB_PROPS:
            props[prop] = getattr(self, prop)
            if props[prop] and prop in JobProxy.JOB_PROPS_DUMPS.keys():
                props[prop] = JobProxy.JOB_PROPS_DUMPS[prop](props[prop])
        return props

    def details(self):
        """:returns tuple with time of the next run and job structure"""
        return self.next_run, self.to_dict()


class JobsQueue(object):
    """Jobs queue collects jobs list to run one-by-one"""
    def __init__(self, env):
        self.env = env
        self._serialized_jobs = []

    @property
    def job(self):
        """:returns partial to call for executing jobs consequentially"""
        assert self._serialized_jobs, "Cannot create queue job for empty list"
        return functools.partial(queue_jobs, self.env,
                                 self._serialized_jobs)

    def add(self, job_func, *args, **kwargs):
        """Adds job to queue (stored serialized)"""
        job_func = functools.partial(job_func, *args, **kwargs)
        self._serialized_jobs.append(
            self.env.scheduler.serializer.dumps(job_func))


class Scheduler(object):
    """Schedule background tasks"""
    def __init__(self, ctx, mongo):
        import schedule  # trick to hide external module from pickling attempts
        self._job_factory = schedule.Job
        # scheduler in background
        self._worker_thread = threading.Thread(target=self._worker,
                                               name='scheduler')
        self._worker_thread.daemon = True  # thread dies with main
        self._stop_event = threading.Event()
        atexit.register(self.stop)
        # env to de/serialize jobs
        self._ctx = ctx
        with self._ctx:
            self._coll = mongo.db.get_collection('jobs')
            self._coll.create_index([('when', -1)])
            self._coll.create_index([('who', -1)])
        self.env = Env(ctx=ctx, mongo=mongo, scheduler=self)
        self.serializer = callable_ref.Callable(self.env)

    def start(self):
        """Thread starter"""
        LOG.info('scheduler thread start')
        assert not self._worker_thread.is_alive()
        self._stop_event.clear()
        self._worker_thread.start()

    def stop(self):
        """Awaiting current task_logging finish and shutdown then"""
        LOG.info('scheduler thread stop')
        if self._worker_thread.is_alive():
            self._stop_event.set()
            self._worker_thread.join()

    def every(self, interval=1):
        """Schedule a new periodic job."""
        job = self._job_factory(interval)
        return JobProxy(job, self)

    def do_async(self, job_func, *args, **kwargs):
        """Run job async immediately"""
        self.every().second.do_once(job_func, *args, **kwargs)

    @contextlib.contextmanager
    def create_jobs_queue(self):
        """Creates context manager, executable on finish"""
        yield JobsQueue(self.env)

    def serialize_job(self, job, update=False):
        """Serialize and save job to MongoDB for async run"""
        assert job.get_id()
        if update and job.exec_once:
            return self._remove_job(job)
        timestamp, job_attributes = job.details()
        update_op = '$set' if update else '$min'
        with self._ctx:
            LOG.info('scheduler: queue job %s at %s (%s)', job.get_id(),
                     timestamp, update_op)
            self._coll.update_one(
                {'_id': job.get_id()},
                {
                    update_op: {
                        'when': timestamp,
                    },
                    '$setOnInsert': {
                        'what': job_attributes,
                        'who': None,
                    },
                }, upsert=True)

    def _restart_job(self, job):
        """Detach job from current process"""
        with self._ctx:
            req = self._coll.update_one(
                {'_id': job.get_id()},
                {'$set': {'who': None}}
            )
            assert req.matched_count == 1

    def _defer_job(self, job):
        """Postpone job for some time"""
        with self._ctx:
            req = self._coll.update_one(
                {'_id': job.get_id()},
                {'$set': {'who': None,
                          'when': (datetime.datetime.now() +
                                   datetime.timedelta(minutes=1))}}
            )
            assert req.matched_count == 1

    def _replace_job(self, job, job_func):
        """Replace job_func for task"""
        assert not callable_ref.equals_soft(job.job_func, job_func)
        job.job_func = job_func
        with self._ctx:
            req = self._coll.update_one(
                {'_id': job.get_id()},
                {'$set': {'who': None,
                          'what': job.to_dict()}}
            )
            assert req.matched_count == 1

    def _remove_job(self, job):
        """Remove job from pending queue"""
        with self._ctx:
            req = self._coll.delete_one({
                '_id': job.get_id(),
            })
            assert req.deleted_count == 1

    def _find_next_job(self):
        """Lookup for available jobs to execute"""
        with self._ctx:
            workers = self._coll.distinct('who')
            unused = [pid for pid in workers
                      if not (pid and psutil.pid_exists(pid))]
            job = self._coll.find_one_and_update(
                {
                    'when': {'$lte': datetime.datetime.now()},
                    'who': {'$in': unused},
                },
                {
                    '$set': {'who': os.getpid()}
                },
                sort=[('when', -1)])
        return job

    def _worker(self):
        """Background thread function"""
        while not self._stop_event.is_set():
            job_dict = self._find_next_job()
            if not job_dict:
                time.sleep(0)
                continue
            job = JobProxy.from_dict(self._job_factory(1),
                                     self, job_dict['what'])
            LOG.info('scheduler: enter job %s for process #%d (after %s)',
                     job.get_id(), os.getpid(), job_dict['who'])
            self._run_job(job)
            LOG.info('scheduler: leave job %s for process #%d',
                     job.get_id(), os.getpid())

    def _run_job(self, job):
        """Process job results"""
        try:
            LOG.info('scheduler: start job ' + job.get_id())
            with self.env.ctx:
                job_res = job.run()
            LOG.info('scheduler: finish job ' + job.get_id())
            self.serialize_job(job, update=True)
            return job_res
        except RemoveJob:
            LOG.info('scheduler: remove job ' + job.get_id())
            self._remove_job(job)
        except RestartJob:
            LOG.info('scheduler: restart job ' + job.get_id())
            self._restart_job(job)
        except DeferJob:
            LOG.info('scheduler: defer job ' + job.get_id())
            self._defer_job(job)
        except ReplaceJob as new_job:
            LOG.info('scheduler: replace job ' + job.get_id())
            self._replace_job(job, new_job.func)
        return None
