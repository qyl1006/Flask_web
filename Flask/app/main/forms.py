from flask_wtf import Form
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User
from flask_pagedown.fields import PageDownField   ##Markdown富文本编辑器


##用户资料编辑表单
class EditProfileForm(Form):
	username = StringField('用户名', validators=[Required(), Length(1, 64), 
												Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
												'用户名必须只能有字母、数字、点或下划线')])
	name = StringField('姓名', validators=[Length(0, 64)])
	location = StringField('所子城市', validators=[Length(0, 64)])
	about_me = TextAreaField('自我简介/此时的心情心态状态')
	submit = SubmitField('确认提交')
	
###管理员使用的资料编辑表单
class EditProfileAdminForm(Form):
	email = StringField('邮箱地址', validators=[Required(), Length(1, 64), Email()])
	##下面username中使用Regexp函数  正则表达式验证输入值username
	username = StringField('用户名', validators=[Required(), Length(1, 64), 
												Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
												'用户名必须只能有字母、数字、点或下划线')])
	confirmed = BooleanField('记住我')     ##记住上面两个值，验证函数验证时好使用这个对象
	role = SelectField('用户角色', coerce=int) ##下拉列表，，可选值由choices获取
	name = StringField('姓名', validators=[Length(0, 64)])
	location = StringField('所在城市', validators=[Length(0, 64)])
	about_me = TextAreaField('自我简介/此时的心情心态状态')
	submit = SubmitField('确认修改')
	
	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm, self).__init__(*args, **kwargs)
		self.role.choices = [(role.id, role.name)
							  for role in Role.query.order_by(Role.name).all()]
		self.user = user
	##验证函数
	def validate_email(self, field):
		if field.data != self.user.email and \
				User.query.filter_by(email=field.data).first():
			raise ValidationError('该邮箱已存在')
				
	def validate_username(self, field):
		if field.data != self.user.username and \
				User.query.filter_by(username=field.data).first():
			raise ValidationError('该用户名已存在')

###博客文章body的表单
class PostForm(Form):
	body = PageDownField('你想写点什么吗？', validators=[Required()])
	submit = SubmitField('提交')	
	
###用户评论输入的表单
class CommentForm(Form):
	body = StringField('请输入您的评论', validators=[Required()])
	submit = SubmitField('评论')
