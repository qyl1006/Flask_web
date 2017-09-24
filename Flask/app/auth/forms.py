from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(Form):
	email = StringField('邮箱', validators=[Required(), Length(1, 64),
											 Email()])
	password = PasswordField('密码', validators=[Required()])
	remember = BooleanField('让我保持登陆状态')
	submit = SubmitField('确认')

class RegistrationForm(Form):
	email = StringField('电子邮箱', validators=[Required(), Length(1, 64), 
											Email(message= u'请输入有效的邮箱地址，比如：mayun@qq.com')])
	username = StringField('用户名', validators=[
		Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
										  '用户名必须包含有字母、数字、点或下划线')])
	password = PasswordField('设置密码', validators=[
		Required(), EqualTo('password2', message='两次密码输入不相同')])
	password2 = PasswordField('确认密码', validators=[Required()])
	submit = SubmitField('确认注册')
	
	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('该邮箱已被注册')
			
	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('该用户名已占用')

##自己尝试写更改密码的方法
class Old_password_modifiedForm(Form):
	old_password = PasswordField('输入旧密码', validators=[Required()])
	new_password = PasswordField('输入你的新密码', validators=[
								Required(), EqualTo('new_password2', message='两次密码输入不相同')])
	new_password2 = PasswordField('再次输入你的新密码密码', validators=[Required()])
	submit = SubmitField('确认更改')
	
