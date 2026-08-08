import os
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 取消管理员权限的验证密码
ADMIN_REVOKE_PASSWORD = '36619778'

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['SECRET_KEY'] = 'cloud-drive-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clouddrive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

db = SQLAlchemy(app)

# 邮件配置
EMAIL_CONFIG = {
    'smtp_server': 'smtp.qq.com',
    'smtp_port': 465,
    'email': '2690180230@qq.com',
    'password': 'ltbunoytmpixdged'
}

# 根存储目录（可配置多个硬盘路径）
STORAGE_ROOTS = [os.path.join(BASE_DIR, 'storage')]

class StorageSpace(db.Model):
    """存储空间（文件夹）"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    path = db.Column(db.String(500), nullable=False, unique=True)
    max_capacity = db.Column(db.BigInteger, default=1024*1024*1024)  # 单空间最大容量
    used_storage = db.Column(db.BigInteger, default=0)
    is_active = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)
    is_readonly = db.Column(db.Boolean, default=False)  # 只读模式：公共空间，所有用户共享，仅管理员可增删
    auto_assign = db.Column(db.Integer, default=0)  # 新用户自动分配容量（MB），0=不分配
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    files = db.relationship('FileRecord', backref='space', lazy='dynamic')
    
    def get_used_storage(self):
        """计算实际使用量（从磁盘读取）"""
        import os
        from libs.utils import get_name_db_size
        total = 0
        for user in self.users:
            user_folder = os.path.join(self.path, user.username)
            if os.path.exists(user_folder):
                for f in os.listdir(user_folder):
                    fp = os.path.join(user_folder, f)
                    if os.path.isfile(fp):
                        total += os.path.getsize(fp)
        return total


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    max_total_storage = db.Column(db.BigInteger, default=1024*1024*1024)  # 用户最大总容量
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    current_space_id = db.Column(db.Integer, db.ForeignKey('storage_space.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    spaces = db.relationship('StorageSpace', secondary='user_space', backref='users', lazy='dynamic')
    current_space = db.relationship('StorageSpace', foreign_keys=[current_space_id])
    files = db.relationship('FileRecord', backref='owner', lazy='dynamic')
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)
    
    def get_total_used(self):
        """获取用户总使用量"""
        total = 0
        for space in self.spaces:
            total += space.get_used_storage()
        return total


class UserSpace(db.Model):
    """用户与存储空间的关联表"""
    __tablename__ = 'user_space'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    space_id = db.Column(db.Integer, db.ForeignKey('storage_space.id'), nullable=False)
    max_capacity = db.Column(db.BigInteger, default=100*1024*1024)  # 用户在该空间的最大容量，默认100MB
    assigned_at = db.Column(db.DateTime, default=datetime.now)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'space_id', name='uq_user_space'),)


class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    space_id = db.Column(db.Integer, db.ForeignKey('storage_space.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.now)


class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), default='register')  # register / pwd_reset
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_used = db.Column(db.Boolean, default=False)