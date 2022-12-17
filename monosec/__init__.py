from flask import Flask
from flask_login import login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_authorize import Authorize
#from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from monosec.config import Config
from flask_session import Session
import logging, os


session = Session()


logging.basicConfig(level=logging.DEBUG,
format='%(asctime)s %(levelname)s %(message)s',
      filename='monosec.log',
      filemode='w')

# logging.getLogger("requests").setLevel(logging.WARNING)
# logging.basicConfig(filename='monosec.log') # replace with env var
# logging.basicConfig(level=logging.INFO)

authorize = Authorize()
#mail = Mail()
bcrypt = Bcrypt()
db = SQLAlchemy()
login_manager = LoginManager()
login_required.login_view = 'users.login'
login_required.login_message_category = 'info'
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__,template_folder='templates')
    app.config.from_object(Config)
    app.logger.info("Starting monosec application")
    from monosec.users.routes import users
    from monosec.auth.routes import creds
    from monosec.posts.routes import posts
    from monosec.src.routes import main
    from monosec.error_handler.handlers import errors

    db.init_app(app)
    #mail.init_app(app)
    authorize.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    session.init_app(app)
    session.permanent = True

    app.register_blueprint(main)
    app.register_blueprint(users)
    app.register_blueprint(creds)
    app.register_blueprint(posts)
    app.register_blueprint(errors)

    with app.app_context():
        db.create_all()

    app.logger.info("Database creation done.")
    return app

    