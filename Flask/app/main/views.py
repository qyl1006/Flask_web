from datetime import datetime  #关于渲染时间的一个变量
from flask import render_template, session, redirect, url_for, current_app, flash, request, make_response
from flask_login import login_required, current_user
from . import main
from .forms import PostForm, EditProfileForm, EditProfileAdminForm, CommentForm
from .. import db
from ..models import User, Role, Permission, Post, Follow, Comment
from ..email import send_email
from ..decorators import admin_required, permission_required

##处理首页博客文章的路由
@main.route('/', methods=['GET', 'POST'])
def index():
	form = PostForm()
	if current_user.can(Permission.WRITE_ARTICLES) and \
			form.validate_on_submit():
		post = Post(body=form.body.data,
					author=current_user._get_current_object())   ###这里的current_user._get_current_object()的用法，是提取真正的对象   优点懵逼！！？
		db.session.add(post)
		return redirect(url_for('.index'))
	###显示所有博客文章或只显示所关注用户的文章，show_followed为非空字符串时，只显示关注用户的文章
	show_followed = False
	if current_user.is_authenticated:
		show_followed = bool(request.cookies.get('show_followed', ''))  ##获取字典中show_followed的值
	if show_followed:
		query = current_user.followed_posts
	else:
		query = Post.query              ###只能说这些query使用的666, 精巧。。lazy='dynamic'
	page = request.args.get('page', 1, type=int)
	pagination = query.order_by(Post.timestamp.desc()).paginate(
				page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
				error_out=False)
				##error_out=False,当请求页数超出范围，则会返回404错误 
	posts = pagination.items
	return render_template('index.html', form=form, posts=posts,
							show_followed=show_followed, pagination=pagination)


#用户资料页面的路由。很好奇为什么放这里了，app/auth/views与app/main/views这两个添加路由.py有什么区别？
@main.route('/user/<username>')
def user(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		abort(404)
	page = request.args.get('page', 1, type=int)	
	####下面找当前用户的posts属性(对应Post类里面的所有博客) 
	pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
	posts = pagination.items
	return render_template('user.html', user=user, posts=posts, pagination=pagination)
	
	
##用户资料编辑路由
@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
	form = EditProfileForm()
	if form.validate_on_submit():
		current_user.username = form.username.data
		current_user.name = form.name.data
		current_user.location = form.location.data
		current_user.about_me = form.about_me.data
		db.session.add(current_user)      ##一直很好奇为什么后面不加上db.session.commit() ??
		flash('您的个人资料已更新')
		return redirect(url_for('.user', username=current_user.username))
	form.username.data = current_user.username
	form.name.data = current_user.name
	form.location.data = current_user.location
	form.about_me.data = current_user.about_me
	return render_template('edit_profile.html', form=form)
	
###管理员的资料编辑路由
@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
	user = User.query.get_or_404(id)
	form = EditProfileAdminForm(user=user)
	if form.validate_on_submit():
		user.email = form.email.data
		user.username = form.username.data
		user.confirmed = form.confirmed.data
		user.role = Role.query.git(form.role.data)
		user.name = form.name.data
		user.location = form.location.data
		user.about_me = form.about_me.data
		db.session.add(user)
		flash('这些资料已更新')
		return redirect(url_for('.user', username=user.username))
	form.email.data = user.email
	form.username.data = user.username
	form.confirmed.data = user.confirmed
	form.role.data = user.role_id
	form.name.data = user.name
	form.location.data = user.location
	form.about_me.data = user.about_me
	return render_template('edit_profile.html', form=form, user=user)
		
###文章固定链接路由。。。。加功能。。支持博客文章评论
@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
	post = Post.query.get_or_404(id)
	form = CommentForm()
	if form.validate_on_submit():
		comment = Comment(body=form.body.data,
							post=post,
							author=current_user._get_current_object())
		db.session.add(comment)
		flash('你已发布评论')
		return redirect(url_for('.post', id =post.id, page=-1))
	page = request.args.get('page', 1, type=int)
	if page == -1:
		page = (post.comments.count() - 1) /\
				current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
	pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
				page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
				error_out=False)
	comments = pagination.items
	return render_template('post.html', posts=[post], form=form, comments=comments,
										pagination=pagination)


##编辑文章的路由
@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
	post = Post.query.get_or_404(id)
	if current_user != post.author and \
						not current_user.can(Permission.ADMINISTER):
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.body = form.body.data
		db.session.add(post)
		flash('该文章已更新')
		return redirect(url_for('.post', id=post.id))
	form.body.data = post.body
	return render_template('edit_post.html', form=form)
	
### "关注他人"的路由
@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('无效用户')
		return redirect(url_for('.index'))
	if current_user.is_following(user):
		flash('你已经关注了该用户')
		return redirect(url_for('.user', username=username))
	current_user.follow(user)
	flash('你现在已关注了 %s' % username)
	return redirect(url_for('.user', username=username))
	
### ‘取消关注他人’的路由
@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('无效用户名')
		return redirect(url_for(',index'))
	if not current_user.is_following(user):
		flash('你没有关注该用户')
		return redirect(url_for('.user', username=username))
	current_user.unfollow(user)
	flash('你已经取消关注 %s' % username)
	return redirect(url_for('.user', username=username))


### user页面 列出user所有 粉丝用户（分页）列表及时间点  的路由
@main.route('/followers/<username>')
def followers(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('无效用户名')
		return redirect(url_for('.index'))
	page = request.args.get('page', 1, type=int)
	pagination = user.followers.paginate(page,
						per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
						error_out=False)
	follows = [{'user': item.follower, 'timestamp': item.timestamp}
				for item in pagination.items]
	return render_template('followers.html', user=user, title="的粉丝",
							endpoint='.followers', pagination=pagination,
							follows=follows)
							
####user页面 列出关注user的所有用户（分页）列表及时间点 de 路由
@main.route('/followed_by/<username>')
def followed_by(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		flash('无效用户名')
		return redirect(url_for('.index'))
	page = request.args.get('page', 1, type=int)
	pagination = user.followed.paginate(page,
						per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
						error_out=False)
	follows = [{'user': item.followed, 'timestamp': item.timestamp}
				for item in pagination.items]
	return render_template('followers.html', user=user, title="关注的人",
							endpoint='.followed_by', pagination=pagination,
							follows=follows)


########查询所有文章还是所关注用户的文章， 结合首页‘/’视图函数使用
#查询所有用户文章
@main.route('/all')
@login_required
def show_all():
	resp = make_response(redirect(url_for('.index')))
	resp.set_cookie('show_followed', '', max_age=30*24*60*60)  ##cookie名show_followed的值为None，max_age设置过期时间,单位为秒s
	return resp
	
###查询使关注用户的文章
@main.route('/followed')
@login_required
def show_followed():
	resp = make_response(redirect(url_for('.index')))
	resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
	return resp


####管理评论的路由
@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
	page = request.args.get('page', 1, type=int)
	pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
					page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
					error_out=False)
	comments = pagination.items
	return render_template('moderate.html', comments=comments,
							pagination=pagination, page=page)

##评论管理路由， 禁用评论或启用评论
##启用评论
@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
	comment = Comment.query.get_or_404(id)
	comment.disabled = False
	db.session.add(comment)
	return redirect(url_for('.moderate',
								page=request.args.get('page', 1, type=int)))
								
#禁用评论
@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
	comment = Comment.query.get_or_404(id)
	comment.disabled = True
	db.session.add(comment)
	return redirect(url_for('.moderate',
								page=request.args.get('page', 1, type=int)))
