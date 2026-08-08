import os
from libs.config import app, db, User, StorageSpace, BASE_DIR
from libs.routes import (
    register_auth_routes,
    register_file_routes,
    register_account_routes,
    register_admin_routes,
    register_index_route
)
from libs.utils import create_space_folder

with app.app_context():
    db.create_all()
    
    # 自动迁移：为旧数据库添加缺失列
    import sqlite3
    db_path = os.path.join(BASE_DIR, 'instance', 'clouddrive.db')
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('ALTER TABLE storage_space ADD COLUMN auto_assign INTEGER DEFAULT 0')
            conn.commit()
        except:
            pass
        conn.close()
    
    admin_exists = User.query.filter_by(is_admin=True).first()
    if not admin_exists:
        admin = User(
            username='admin',
            email='admin@clouddrive.com',
            is_admin=True,
            is_verified=True,
            max_total_storage=1024*1024*1024*100  # 100GB
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("=== 管理员账号已自动创建 ===")
        print("用户名: admin")
        print("密码: admin123")
        print("================================")
    
    default_space = StorageSpace.query.filter_by(is_active=True).first()
    if not default_space:
        default_path = os.path.join(BASE_DIR, 'storage', 'default')
        space = StorageSpace(
            name='默认存储空间',
            path=default_path,
            max_capacity=1024*1024*1024,  # 1GB
            is_active=True,
            is_default=True
        )
        db.session.add(space)
        db.session.commit()
        create_space_folder(space)
        print("=== 默认存储空间已创建 ===")
        print(f"路径: {default_path}")
        print("================================")

register_auth_routes()
print("DEBUG: auth routes registered")

register_file_routes()
print("DEBUG: file routes registered")

register_account_routes()
print("DEBUG: account routes registered")

register_admin_routes()
print("DEBUG: admin routes registered")

register_index_route()
print("DEBUG: index route registered")

print("\n=== All Registered Routes ===")
for rule in app.url_map.iter_rules():
    methods = ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
    print(f"  {rule.rule} ({methods}) -> {rule.endpoint}")
print("=============================\n")

if __name__ == '__main__':
    try:
        from waitress import serve
        print("Running with Waitress production WSGI server...")
        serve(app, host='0.0.0.0', port=8897, threads=16)
    except ImportError:
        print("Running with Flask development server...")
        app.run(host='0.0.0.0', port=8897)