import smtplib
import random
import string
import os
import sqlite3
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from libs.config import EMAIL_CONFIG, db, EmailVerification, StorageSpace
from datetime import datetime, timedelta


def send_verification_email(email, code, subject=None, body=None):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_CONFIG['email']
    msg['To'] = email
    msg['Subject'] = subject or '网盘注册验证码'
    if body is None:
        body = f'您的验证码是：{code}，有效期5分钟。请勿泄露给他人。'
    msg.attach(MIMEText(body, 'plain', 'utf-8'))
    try:
        server = smtplib.SMTP_SSL(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.login(EMAIL_CONFIG['email'], EMAIL_CONFIG['password'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"邮件发送失败: {e}")
        return False


def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))


def create_verification(email, purpose='register'):
    EmailVerification.query.filter_by(email=email, purpose=purpose, is_used=False).delete()
    code = generate_verification_code()
    verification = EmailVerification(email=email, code=code, purpose=purpose, created_at=datetime.now())
    db.session.add(verification)
    db.session.commit()
    return code


def verify_code(email, code, purpose='register'):
    verification = EmailVerification.query.filter_by(
        email=email, code=code, purpose=purpose, is_used=False
    ).first()
    if not verification:
        return False
    if verification.created_at < datetime.now() - timedelta(minutes=10):
        return False
    verification.is_used = True
    db.session.commit()
    return True


def format_file_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_space_storage_info(space):
    max_capacity = space.max_capacity
    used_storage = space.get_used_storage()
    percentage = (used_storage / max_capacity * 100) if max_capacity > 0 else 0
    return {
        'max': format_file_size(max_capacity),
        'used': format_file_size(used_storage),
        'percentage': round(percentage, 2)
    }


def get_user_total_storage_info(user):
    max_total = user.max_total_storage
    used_total = user.get_total_used()
    percentage = (used_total / max_total * 100) if max_total > 0 else 0
    return {
        'max': format_file_size(max_total),
        'used': format_file_size(used_total),
        'percentage': round(percentage, 2)
    }


def create_space_folder(space):
    if not os.path.exists(space.path):
        os.makedirs(space.path, exist_ok=True)


def get_user_folder(user, space):
    # 只读空间：所有用户共享同一目录，不按用户名分文件夹
    if space.is_readonly:
        if not os.path.exists(space.path):
            os.makedirs(space.path, exist_ok=True)
        return space.path
    user_folder = os.path.join(space.path, user.username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder, exist_ok=True)
    return user_folder


def get_name_db_path(user_folder):
    return os.path.join(user_folder, 'name.db')


def init_name_db(user_folder):
    db_path = get_name_db_path(user_folder)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            md5 TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            upload_time TEXT NOT NULL,
            is_preserved INTEGER DEFAULT 0
        )
    ''')
    # 兼容旧数据库：添加 is_preserved 列
    try:
        cursor.execute('ALTER TABLE files ADD COLUMN is_preserved INTEGER DEFAULT 0')
    except:
        pass
    conn.commit()
    conn.close()
    return db_path


def add_file_to_name_db(user_folder, md5, original_name, is_preserved=False):
    db_path = init_name_db(user_folder)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO files (md5, original_name, upload_time, is_preserved) VALUES (?, ?, ?, ?)',
        (md5, original_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1 if is_preserved else 0)
    )
    conn.commit()
    conn.close()


def remove_file_from_name_db(user_folder, md5):
    db_path = get_name_db_path(user_folder)
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM files WHERE md5 = ?', (md5,))
        conn.commit()
        conn.close()


def get_file_info_from_name_db(user_folder, md5):
    db_path = get_name_db_path(user_folder)
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT original_name, upload_time FROM files WHERE md5 = ?', (md5,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return {'original_name': result[0], 'upload_time': result[1]}
    return None


def get_all_files_from_name_db(user_folder):
    db_path = get_name_db_path(user_folder)
    if not os.path.exists(db_path):
        return []
    # 先调用 init_name_db 确保列已升级
    init_name_db(user_folder)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT md5, original_name, upload_time FROM files ORDER BY upload_time DESC')
    results = cursor.fetchall()
    conn.close()
    
    # 从 JSON 加载保留列表
    preserve_list = load_preserve_list(user_folder)
    
    return [
        {
            'md5': r[0],
            'original_name': r[1],
            'upload_time': r[2],
            'is_preserved': r[0] in preserve_list
        }
        for r in results
    ]


def get_name_db_size(user_folder):
    db_path = get_name_db_path(user_folder)
    if os.path.exists(db_path):
        return os.path.getsize(db_path)
    return 0


def rename_file_in_name_db(user_folder, md5, new_name):
    """重命名文件的显示名称（不改源文件）"""
    db_path = get_name_db_path(user_folder)
    if not os.path.exists(db_path):
        return False
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('UPDATE files SET original_name = ? WHERE md5 = ?', (new_name, md5))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def get_preserve_json_path(user_folder):
    return os.path.join(user_folder, 'preserve.json')


def load_preserve_list(user_folder):
    """加载保留文件列表（JSON）"""
    json_path = get_preserve_json_path(user_folder)
    if os.path.exists(json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def save_preserve_list(user_folder, preserve_list):
    """保存保留文件列表（JSON）"""
    json_path = get_preserve_json_path(user_folder)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(preserve_list, f, ensure_ascii=False, indent=2)


def toggle_preserve_file(user_folder, md5):
    """切换文件的保留标记，保留的文件记录到同目录的 preserve.json"""
    preserve_list = load_preserve_list(user_folder)
    
    if md5 in preserve_list:
        # 取消保留
        del preserve_list[md5]
        save_preserve_list(user_folder, preserve_list)
        return True
    else:
        # 标记保留：从 name.db 获取原始名称
        db_path = get_name_db_path(user_folder)
        if not os.path.exists(db_path):
            return False
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT original_name FROM files WHERE md5 = ?', (md5,))
        result = cursor.fetchone()
        conn.close()
        if not result:
            return False
        
        preserve_list[md5] = {
            'original_name': result[0],
            'preserved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        save_preserve_list(user_folder, preserve_list)
        return True


def is_file_preserved(user_folder, md5):
    """检查文件是否被标记保留"""
    preserve_list = load_preserve_list(user_folder)
    return md5 in preserve_list


def build_index_for_readonly_space(space_path):
    """为只读空间构建文件索引（扫描目录中未被索引的文件）"""
    if not os.path.exists(space_path):
        return 0
    
    db_path = init_name_db(space_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    indexed_count = 0
    for filename in os.listdir(space_path):
        file_path = os.path.join(space_path, filename)
        if not os.path.isfile(file_path):
            continue
        
        # 跳过 name.db 文件
        if filename == 'name.db':
            continue
        
        # 检查是否已索引
        cursor.execute('SELECT md5 FROM files WHERE md5 = ?', (filename,))
        if cursor.fetchone():
            continue
        
        # 计算 MD5 并插入索引
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        md5 = hasher.hexdigest()
        
        # 如果文件名就是 MD5（32位），直接使用；否则重命名文件为 MD5
        if len(filename) == 32:
            file_md5 = filename
        else:
            # 重命名文件为 MD5（保留扩展名用于下载时识别）
            import shutil
            ext = os.path.splitext(filename)[1]  # 如 .pdf
            new_name = md5 + ext
            new_path = os.path.join(space_path, new_name)
            
            # 如果目标已存在，跳过
            if os.path.exists(new_path):
                file_md5 = new_name
            else:
                shutil.move(file_path, new_path)
                file_md5 = new_name
        
        cursor.execute(
            'INSERT OR REPLACE INTO files (md5, original_name, upload_time) VALUES (?, ?, ?)',
            (file_md5, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        indexed_count += 1
    
    conn.commit()
    conn.close()
    return indexed_count


def compute_file_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()