from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from . import mail

#异步发送邮件，比之前的快一些
def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)		
#电子邮件发送功能
#send_email()的参数，to是发给谁，subject邮件主题，template调用哪个模板，**kwargs关键字参数,是字典dict
def send_email(to, subject, template, **kwargs):
	app = current_app._get_current_object()
	msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
					sender=app.config['FLASKY_MAIL_SENDER'], 
					recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg])
	thr.start()
	return thr
