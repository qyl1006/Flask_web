from . import db, login_manager
from werkzeug .security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request
from . import db
from datetime import datetime
import hashlib
from markdown import markdown
import bleach

#权限常量,权限类
class Permission:
	FOLLOW = 0x01
	COMMENT = 0x02
	WRITE_ARTICLES = 0x04
	MODERATE_COMMENTS = 0x08
	ADMINISTER = 0x80

#定义Role模型
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	default = db.Column(db.Boolean, default=False, index=True)
	permissions = db.Column(db.Integer)
	##与User模型的关系  一对User
	users = db.relationship('User', backref='role', lazy='dynamic') #与User类相链接的桥梁
	
#在数据库中创建角色，使用了静态方法;True与False各为对应default的值	
	@staticmethod
	def insert_roles():
		roles = {
			'User': (Permission.FOLLOW | 
					 Permission.COMMENT | 
					 Permission.WRITE_ARTICLES, True),
			'Moderator': (Permission.FOLLOW | 
						  Permission.COMMENT | 
						  Permission.WRITE_ARTICLES | 
						  Permission.MODERATE_COMMENTS, False),
			'Administrator': (0xff, False)
		}
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			role.permissions = roles[r][0]
			role.default = roles[r][1]
			db.session.add(role)
		db.session.commit()
	
	def __repr__(self):
		return '<Role %r>' % self.name
	

#####多对多关系的关联表。。。现定义成Follow模型###### 之前这模型放在最后面，然后User.followed一直找不到Follow， 套路我一波，气
class Follow(db.Model):
	__tablename__ = 'follows'
	follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True)   ##外键，'多'的一侧，关注者的id。。user.id， 设为主键
	followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True) ##外键， '多'的一侧，被关注者的id。。user.id。。设主键
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)  ## 用来记录时间点

	
##定义文章博客Post模型
class Post(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text)  #文章内容
	body_html = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow) #时间，距发布body多久
	##与User模型关系 多对User
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))	#外键，和users表相连  
	comments = db.relationship('Comment', backref='post', lazy='dynamic') ## 一对多关系，’一‘侧

	def __repr__(self):
		return '<Post %r>' % self.body
		
##########################################################################	
#####以下。。使用ForgeryPy包生成大量的博客文章，用测试用

	@staticmethod  
	def generate_fake(count=100):
		from random import seed,randint  
		import forgery_py  
          
		seed()  
		user_count = User.query.count()        #这行是查询一共有生成了多少虚拟用户  
		for i in range(count):
			u = User.query.offset(randint(0,user_count-1)).first()  
			p = Post(body = forgery_py.lorem_ipsum.sentences(randint(1,3)),  
					timestamp = forgery_py.date.date(True),  
					author = u)            #这一行，将用户和所发的文章绑定了起来  
		db.session.add(p)  
		db.session.commit()  
#######################################################################
	
	####在Post模型处理Markdown文本
	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
						'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
						'h1', 'h2', 'h3', 'p']
		target.body_html = bleach.linkify(bleach.clean(markdown(value,output_format='html'),
														tags=allowed_tags, strip=True))
db.event.listen(Post.body, 'set', Post.on_changed_body)
	
	
	

##定义User模型	
class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64), unique=True, index=True)
	username = db.Column(db.String(64), unique=True, index=True)
	password_hash = db.Column(db.String(128))
	##与Role模型的关系 多对Role
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))  #外键，与roles表相连
	confirmed = db.Column(db.Boolean, default=False)  #confirmed默认属性为False
	##与Post模型关系 一对Post
	posts = db.relationship('Post', backref='author', lazy='dynamic') #与Post类相连接的桥梁
	comments = db.relationship('Comment', backref='author', lazy='dynamic')##与Comment的关系， 一对多，’一‘侧
	
	###用户个人信息字段
	name = db.Column(db.String(64))
	location = db.Column(db.String(64))
	about_me = db.Column(db.Text())
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)

# 使用两个一对多关系实现的多对多关系。。
	followed = db.relationship('Follow',
								foreign_keys=(Follow.follower_id),
								backref=db.backref('follower', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
#			##foreign_key指定外键，db.backref()参数回引Follow模型，lazy='dynamic'是User这侧的，
#			## 用来返回‘多’那侧的记录：follower,时间。cascade参数是和删除对象时候，关联表格里面的内容会不会一起删掉有关系
#			###最后这个 关注者列表吧followed， 就是说 我关注的人 的表
	followers = db.relationship('Follow',
								foreign_keys=[Follow.followed_id],
								backref=db.backref('followed', lazy='joined'),
								lazy='dynamic',
								cascade='all, delete-orphan')
			#####大致和上面followed相同，这个是 被关注者列表followers， 关注自己的人 自己粉丝 的表
######关注关系的辅助方法  为什么他们可以加过滤器使用？因为lazy='dynamic'，返回查询对象，可以添加过滤器，不知道对不对
###第一个 如果这个人user我没有关注，那我就关注她
	def follow(self, user):
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)
			
###第二个 如果这个人user我关注了她，我就取消关注她， 删除delete
	def unfollow(self, user):
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			db.session.delete(f)
			
####第三个 这个人user在我所有我所关注人当中，不是None的，就返回True
	def is_following(self, user):
		return self.followed.filter_by(followed_id=user.id).first() is not None
####第四个 这个人user在所有关注我的人当中，我是被关注的，，user是我的粉丝的话。。不是None的，返回True
	def is_followed_by(self, user):
		return self.followers.filter_by(follower_id=user.id).first() is not None



	
	###在User模型中加入密码散列，分别用于在注册用户和验证用户环节
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')  ##密码只写属性

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)  #密码的散列值
		
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password) ##比较用户输入的密码与数据库里
																	##散列值，一致就返回True

#? 不知道对不对！！加载用户的回调函数
	@login_manager.user_loader
	def load_user(user_id):
		return User.query.get(int(user_id))
		
	
		

###确认用户帐号
    #加密签名,返回令牌,有效期1h
	def generate_confirmation_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})
		
	#验证令牌，并判定令牌id与current_user.id是否一致，通过就把confirmed属性设为True
	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)  ##? 不明白token为什么是令牌字符串！？哪里有赋值？
		except:
			return False
		if data.get('confirm') != self.id:
			return False
		self.confirmed = True
		db.session.add(self)
		return True
	
	###定义默认的用户角色，
	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		if self.role is None:
			if self.email == current_app.config['FLASKY_ADMIN']:
				self.role = Role.query.filter_by(permissions=0xff).first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()
	##新建用户时把用户设为自己的关注者
		self.follow(self)
	
	###检查用户是否有指定的权限
	def can(self, permissions):
		return self.role is not None and \
			(self.role.permissions & permissions) == permissions
			
	def is_administrator(self):
		return self.can(Permission.ADMINISTER)
		
	###刷新用户的最后访问时间
	def ping(self):
		self.last_seen = datetime.utcnow()
		db.session.add(self)	
	
	####生成Gravatar URL 一个头像服务网站的URL，通过计算每个邮箱地址的MD5散列值.
	def gravatar(self, size=100, default='identicon', rating='g'):
		if request.is_secure:  ###判断request是否为https 
			url = 'https://secure.gravatar.com/acatar'
		else:
			url = 'http://www.gravatar.com/avatar'
		hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
		return '{url}/{hash}?s={size}&d={default}&r=[rating]'.format(
			url=url, hash=hash, size=size, default=default, rating=rating)
			
#####################################################################
###以下。。使用ForgeryPy包生成大量的虚拟用户和，用测试用
	@staticmethod
	def generate_fake(count=100):
		from sqlalchemy.exc import IntegrityError
		from random import seed
		import forgery_py
		
		seed()
		for i in range(count):
			u = User(email=forgery_py.internet.email_address(),
					 username=forgery_py.internet.user_name(True),
					 password=forgery_py.lorem_ipsum.word(),
					 confirmed=True,
					 name=forgery_py.name.full_name(),
					 location=forgery_py.address.city(),
					 about_me=forgery_py.lorem_ipsum.sentence(),
					 member_since=forgery_py.date.date(True))
			db.session.add(u)
			try:
				db.session.commit()
			except IntegrityError:
				db.session.rollback()  ##异常就回滚
##################################################################	

##获取所关注用户的文章
	@property            ###装饰器， 作用把followed_posts作为属性来访问
	def followed_posts(self):
		return Post.query.join(Follow, Follow.followed_id == Post.author_id)\
				.filter(Follow.follower_id == self.id)

##########################。。。。创建函数更新数据库。。。#####
###把用户设为自己的关注者
	@staticmethod
	def add_self_follows():
		for user in User.query.all():
			if not user.is_following(user):
				user.follow(user)
				db.session.add(user)
				db.session.commit()

		
			
	def __repr__(self):
		return '<User %r>' % self.username

##定义一个AnonymousUser类，
##将login_manager.anonymous_user设为AnonymousUser类对象，实际上就是未登录状态的current_user 
class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False
		
	def is_administrator(self):
		return False
login_manager.anonymous_user = AnonymousUser
		

######建立用户评论Comment模型
class Comment(db.Model):
	__tablename__ = 'comments'
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text)
	body.html = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	disabled = db.Column(db.Boolean)
	author_id = db.Column(db.Integer, db.ForeignKey('users.id')) #外键 对应User
	post_id = db.Column(db.Integer, db.ForeignKey('posts.id')) #外键 对应Post
	
	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i', 'strong']
		target.body_html = bleach.linkify(bleach.clean(markdown(value,
							output_format='html'), tags=allowed_tags, strip=True))
							
db.event.listen(Comment.body, 'set', Comment.on_changed_body)
