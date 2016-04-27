# slag: Slack Archive

[![MIT Licese](https://img.shields.io/github/license/n8v-guy/slag.svg)](https://github.com/n8v-guy/slag/blob/master/LICENSE)
[![Build Status](https://img.shields.io/travis/n8v-guy/slag.svg)](https://travis-ci.org/n8v-guy/slag)
[![Code Health](https://landscape.io/github/n8v-guy/slag/master/landscape.svg?style=flat)](https://landscape.io/github/n8v-guy/slag/master)
[![Your feedback is greatly appreciated](https://img.shields.io/maintenance/yes/2016.svg)](https://github.com/n8v-guy/slag/issues/new)
[![Kanban board @ waffle.io](https://img.shields.io/github/issues-raw/n8v-guy/slag.svg)](https://waffle.io/n8v-guy/slag)

Slag is an export files viewer for [Slack](https://slack.com), capable to look backward  
**more than 10 000 messages back** (limit on the free [Slack plan](https://slack.com/pricing)), plus:
* limit access only for team members
* full text search through channels archive
* browse channels history back to the beginning
* browse private messages with corresponding access rights
* import new messages on a timer basis
  
**NB**: This service named after [slag glass](https://en.wikipedia.org/wiki/Slag), which is the solid state of **slack** in the meaning of **coal dust**.


### Thanks
Slag uses a number of open source projects to work properly:
* [slacker](https://github.com/os/slacker), Python binding for Slack API
* [Flask](http://flask.pocoo.org/), neat web microframework for Python
* [Bootstrap](https://getbootstrap.com/), great UI boilerplate
* [jQuery](https://jquery.com/), because

### Installation
Deploy this repo to [Heroku](https://www.heroku.com/) dyno, setup [mLab](https://mlab.com/) integration (both are available on the free plan) and put your settings in `bootstrap.py` file. Simple as that.
But just ask me if you have any issues there.

### Development
Want to contribute? Great!  
Just fill the issue on GitHub & create the pull-request.  
