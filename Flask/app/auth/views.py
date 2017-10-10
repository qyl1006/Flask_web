from .. import db
from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, Old_password_modifiedForm, \
		PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from ..email import send_email



@auth.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember.data)
			return redirect(request.args.get('next') or url_for('main.index'))
		flash('用户名或密码错误')
	return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash("你已注销")
	return redirect(url_for('main.index'))
	

##注册帐号	
@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,
					username=form.username.data,
					password=form.password.data)
		db.session.add(user)
		db.session.commit()
		token = user.generate_confirmation_token()
		send_email(user.email, '确认您的帐号', 
					'auth/email/confirm', user=user, token=token)
		flash('已通过email向您发送确认电子邮件')
		return redirect(url_for('main.index'))
	return render_template('auth/register.html', form=form)

#确认用户帐号路由（发的邮件）
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	if current_user.confirm(token):
		flash('您已经确认了您的帐户。 谢谢')
	else:
		flash('确认链接无效或已过期。')
	return redirect(url_for('main.index'))
	
	
# #auth蓝本中的，每次在请求前运行。就是钩子，书中94页有说明
@auth.before_app_request
def before_request():
	   #如果用户是认证过的
	   ##用户未确认，not
	   ###request的网址不是以auth.和static开头的??
	if current_user.is_authenticated:
		###更新已登录用户的访问时间
		current_user.ping()
		if not current_user.confirmed \
			and request.endpoint[:5] != 'auth.' \
			and request.endpoint != 'static':
			return redirect(url_for('auth.unconfirmed'))  #返回到未确认的一个路由
		
#未确人的路由
@auth.route('/unconfirmed')
def unconfirmed():
	#如果用户是非普通用户(is_anonymous对普通用户返回False ??)，或者已确认的，则返回主页
	if current_user.is_anonymous or current_user.confirmed:  
		return redirect(url_for('main.index'))
	return render_template('auth/unconfirmed.html')  #进入未确认页面
			
##重发帐号确认邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	send_email(current_user.email, '确认您的帐号',
				'auth/email/confirm', user=current_user, token=token)
	flash('已经通过电子邮件发送了一封新的确认电子邮件，请注意查收。')
	return redirect(url_for('main.index'))
	

###更改密码
@auth.route('/old_password_modified', methods=['GET', 'POST'])
@login_required
def old_password_modified():
	form = Old_password_modifiedForm()
	if form.validate_on_submit():
		if current_user.verify_password(form.old_password.data):
			current_user.password = form.new_password.data
		db.session.add(current_user)
		db.session.commit()
		flash('你已成功更改密码')
		return redirect(url_for('main.index'))
	return render_template('auth/old_password_modified.html', form=form)

			
###发邮件验证重置密码。。。。。发送email的路由
@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
	if not current_user.is_anonymous:
		return redirect(url_for('main.index'))
	form = PasswordResetRequestForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user:
			token = user.generate_reset_token()
			send_email(user.email, '重置你的密码', 'auth/email/reset_password',
						user=user, token=token, next=request.args.get('next'))
			flash('一封包含验证信息的邮件已发给你，请注意查收')
			return redirect(url_for('auth.login'))
	return render_template('auth/reset_password.html', form=form)
		
#####重置密码，验证邮箱的路由
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
	if not current_user.is_anonymous:
		return redirect(url_for('main.index'))
	form = PasswordResetForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is None:
			return redirect(url_for('main.index'))
		if user.reset_password(token, form.password.data):
			flash('你的密码已更改,请登录')
			return redirect(url_for('auth.login'))
		else:
			return redirect(url_for('main.index'))
	return render_template('auth/reset_password.html', form=form)


#####通过发送邮件验证更换邮箱。。。。发送邮件路由
@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
	form = ChangeEmailForm()
	if form.validate_on_submit():
		if current_user.verify_password(form.password.data):    ###与存在数据的密码(散列值)对比，验证密码的正确性
			new_email = form.email.data
			token = current_user.generate_email_change_token(new_email)
			send_email(new_email, "更换你的邮箱", 'auth/email/change_email',
						user=current_user, token=token)
			flash('一封待确认更换邮箱地址的电子邮件已发送您，请注意查收')
			return redirect(url_for('main.index'))
		else:
			flash('密码不正确')
	return render_template('auth/change_email.html', form=form)

###通过邮件上的链接确认更换邮箱。。。的路由
@auth.route('/change-email/<token>')
def change_email(token):
	if current_user.change_email(token):
		flash('你已成功更换邮箱')
	else:
		flash('无效请求或邮件已过期')
	return redirect(url_for('main.index'))
