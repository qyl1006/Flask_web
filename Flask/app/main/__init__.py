from ..models import Permission
#创建蓝本
from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors

##把Permission类加入模块上下文，。。。。1、搞不懂为什么添加到这个目录下？app/auth/__init__.py可以吗？
###2、这个代码也看不懂! dict字典
@main.app_context_processor
def inject_permission():
	return dict(Permission=Permission)
