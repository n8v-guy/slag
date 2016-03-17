# slag: Slack Archive

Slag is an export files viewer for [Slack](https://slack.com), capable to look backward  
**more than 10 000 messages back** (limit on the free [Slack plan](https://slack.com/pricing)), plus:
* limit access only for team members
* full text search through channels archive
* browse channels history back to the beginning
* import new messages on timer basis [TBD]
* private channels & messages with corresponding access right [TBD]
  
**NB**: This service named after [slag glass](https://en.wikipedia.org/wiki/Slag), which is the solid state of **slack** in the meaning of **coal dust**.


### Thanks
Slag uses a number of open source projects to work properly:
* [slacker](https://github.com/os/slacker), Python binding for Slack API
* [Flask](http://flask.pocoo.org/), neat web microframework for Python
* [Bootstrap](https://getbootstrap.com/), great UI boilerplate
* [jQuery](https://jquery.com/), because

### Installation
Deploy this repo to [Heroku](https://www.heroku.com/) dyno, setup [mLab](https://mlab.com/) integration (both are available on the free plan) and put your settings in `credentials.py` file. Simple as that.
But just ask me if you have any problems here.

### Development
Want to contribute? Great!  
Just fill the issue on GitHub & create the pull-request.  