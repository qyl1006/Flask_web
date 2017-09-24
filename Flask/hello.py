import os
from flask import Flask, render_template, session, redirect, url_for, flash
from flask_script import Manager, Shell
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from datetime import datetime
from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_mail import Mail, Message
from threading import Thread

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
			'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'hard to guess string'

#配置Flask_Mail
app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Flasky]' #一个标识吧，一看就知道'Flasky'发的
app.config['FLASKY_MAIL_SENDER'] = 'Flasky Admin <yuelinqin@163.com>' #发件人，<>前面是昵称吧
app.config['FLASKY_ADMIN'] = os.environ.get('FLASKY_ADMIN') #管理员邮箱

manager = Manager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

mail = Mail(app)

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404
	
@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

#定义一个表单类，参数validators指定验证函数Required()，Submit提交按钮
class NameForm(Form):
	name = StringField('你叫什么名字?', validators=[Required()])
	submit = SubmitField('确认')

#表单的路由方法，validate_on_submit()调用name上的Required()，为True用户输入的就通过
#data属性获取，然后清空表单字段form.name.data；最后(为False直接)渲染表单模块,	
@app.route('/', methods=['GET', 'POST'])
def index():
	form = NameForm()
	if form.validate_on_submit():
		#old_name = session.get('name')
		#if old_name is not None and old_name != form.name.data:
		    #flash('看起来你已经更换之前的名字！')
		user = User.query.filter_by(username=form.name.data).first()
		if user is None:
			user = User(username=form.name.data)
			db.session.add(user)
			session['known'] = False
#若定义了管理员邮箱——True	#发送邮箱实例，#每当输入新的name就自动发邮件给管理员	
 ##mail/new_user 在templates下面子文件夹mail里面,调用名字为new_user的txt和html文件,
 ##网上看的，不知道对不对？	
			if app.config['FLASKY_ADMIN']:  
				send_email(app.config['FLASKY_ADMIN'], 'New User', 
							'mail/new_user', user=user)
		else:
			session['known'] = True    
		session['name'] = form.name.data
		form.name.data = ''
		return redirect(url_for('index'))
	return render_template('index.html', form=form, name=session.get('name'),
							known=session.get('known', False), 
							current_time=datetime.utcnow())
							
#定义Role和User模型
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	users = db.relationship('User', backref='role', lazy='dynamic')
	
	def __repr__(self):
		return '<Role %r>' % self.name
		
class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, index=True)
	rold_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	
	def __repr__(self):
		return '<User %r>' % self.username
		
#异步发送邮件，比之前的快一些
def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)		
#电子邮件发送功能
#send_email()的参数，to是发给谁，subject邮件主题，template调用哪个模板，**kwargs关键字参数,是字典dict
def send_email(to, subject, template, **kwargs):
	msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
					sender=app.config['FLASKY_MAIL_SENDER'], 
					recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg])
	thr.start()
	return thr
		


##为shell命令添加一个上下文，启动shell可自动导入数据库实例和模型
def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role)
manager.add_command('shell', Shell(make_context=make_shell_context))

if __name__ == '__main__':
    manager.run()
