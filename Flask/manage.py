#！/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role, Post, Follow, Permission, Comment
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)

def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role, Post=Post, Follow=Follow,
				Permission=Permission, Comment=Comment)  ##集成Python shell 新添加数据库类可在这添加一个shell上下文，方便
manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
	manager.run()

######部署命令，，
@manager.command
def deploy():
	"""Run deployment tasks"""
	from flask_migrate import upgrade
	from app.models import Role, User
	
	##把数据库迁移到最新修订版本
	upgrade()
	
	###创建用户角色
	Role.insert_roles()
	
	##让所有用户都关注此用户
	User.add_self_follows()
