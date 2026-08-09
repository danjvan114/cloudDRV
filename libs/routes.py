import os
import random
import shutil
from flask import request, jsonify, render_template, redirect, url_for, flash, send_file, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from libs.config import app, db, User, FileRecord, StorageSpace, UserSpace, STORAGE_ROOTS, EmailVerification, ADMIN_REVOKE_PASSWORD, AuthCallback, BASE_DIR
from libs.utils import (
    send_verification_email, create_verification, verify_code,
    format_file_size, get_space_storage_info, get_user_total_storage_info,
    create_space_folder, get_user_folder, get_name_db_path, init_name_db,
    add_file_to_name_db, remove_file_from_name_db, get_file_info_from_name_db,
    get_all_files_from_name_db, get_name_db_size, compute_file_md5,
    build_index_for_readonly_space, rename_file_in_name_db, toggle_preserve_file
)
import datetime


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('权限不足')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def register_auth_routes():
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'GET':
            return render_template('register.html',
                                   backurl=request.args.get('backurl', ''),
                                   uuid=request.args.get('uuid', ''))

        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        verification_code = request.form.get('verification_code')
        backurl = request.form.get('backurl', '')
        uuid = request.form.get('uuid', '')

        if not all([username, email, password, confirm_password, verification_code]):
            flash('请填写完整信息')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        if not username.isascii() or not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            flash('用户名只能包含英文字母、数字、下划线、连字符和点')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        if password != confirm_password:
            flash('两次密码不一致')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        if not verify_code(email, verification_code):
            flash('验证码错误或已过期')
            return redirect(url_for('register', backurl=backurl, uuid=uuid))

        user = User(username=username, email=email, is_verified=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # 为新用户分配自动分配的存储空间
        all_spaces = StorageSpace.query.filter_by(is_active=True).all()
        assigned_spaces = []
        for space in all_spaces:
            # 只读空间：所有用户自动可见，无需分配
            if space.is_readonly:
                if not user.current_space_id:
                    user.current_space_id = space.id
                continue
            # 非只读空间：auto_assign > 0 才分配
            if space.auto_assign > 0:
                user_space = UserSpace(user_id=user.id, space_id=space.id)
                db.session.add(user_space)
                assigned_spaces.append(space)
                if not user.current_space_id:
                    user.current_space_id = space.id
        
        # 设置默认空间
        default_space = StorageSpace.query.filter_by(is_default=True, is_active=True).first()
        if default_space:
            user.current_space_id = default_space.id
        elif assigned_spaces:
            user.current_space_id = assigned_spaces[0].id
        
        db.session.commit()

        flash('注册成功，请登录')
        if uuid and backurl:
            return redirect(url_for('login', uuid=uuid, backurl=backurl))
        return redirect(url_for('login'))

    @app.route('/send_code', methods=['POST'])
    def send_code():
        email = request.json.get('email')
        if not email:
            return jsonify({'success': False, 'message': '请输入邮箱'})

        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': '该邮箱已被注册'})

        code = create_verification(email)
        success = send_verification_email(email, code)

        if success:
            return jsonify({'success': True, 'message': '验证码已发送'})
        else:
            return jsonify({'success': False, 'message': '邮件发送失败'})

    @app.route('/check_user', methods=['POST'])
    def check_user():
        data = request.get_json()
        username = data.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({'exists': True, 'username': user.username})
        return jsonify({'exists': False})

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html',
                                   backurl=request.args.get('backurl', ''),
                                   uuid=request.args.get('uuid', ''))

        username = request.form.get('username')
        password = request.form.get('password')
        backurl = request.form.get('backurl', '')
        uuid = request.form.get('uuid', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin

            # 如果有回调参数，跳转到确认授权页面
            if uuid and backurl:
                callback = AuthCallback.query.filter_by(uuid=uuid).first()
                if callback:
                    callback.user_id = user.id
                    db.session.commit()
                    return redirect(url_for('auth_confirm', uuid=uuid, backurl=backurl))

            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误')
            return redirect(url_for('login', backurl=backurl, uuid=uuid))

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    # ===== 第三方应用回调认证 =====
    @app.route('/auth/callback')
    def auth_callback():
        """第三方应用发起回调，生成 uuid 并记录 backurl"""
        import uuid as uuid_mod
        backurl = request.args.get('backurl', '')
        if not backurl:
            return jsonify({'error': '缺少 backurl 参数'}), 400
        uid = uuid_mod.uuid4().hex
        callback = AuthCallback(uuid=uid, backurl=backurl)
        db.session.add(callback)
        db.session.commit()
        # 跳转到登录页，带上 uuid 和 backurl
        return redirect(url_for('login', uuid=uid, backurl=backurl))

    @app.route('/auth/confirm')
    def auth_confirm():
        """用户登录成功后，确认授权页面"""
        uuid_val = request.args.get('uuid', '')
        backurl = request.args.get('backurl', '')
        if 'user_id' not in session:
            return redirect(url_for('login', uuid=uuid_val, backurl=backurl))
        callback = AuthCallback.query.filter_by(uuid=uuid_val).first()
        if not callback:
            flash('回调记录不存在')
            return redirect(url_for('index'))
        return render_template('auth_confirm.html', uuid=uuid_val, backurl=backurl, username=session.get('username', ''))

    @app.route('/auth/confirm', methods=['POST'])
    def auth_confirm_post():
        """用户确认授权"""
        uuid_val = request.form.get('uuid', '')
        backurl = request.form.get('backurl', '')
        if 'user_id' not in session:
            return redirect(url_for('login'))
        import uuid as uuid_mod
        import secrets
        callback = AuthCallback.query.filter_by(uuid=uuid_val).first()
        if not callback:
            flash('回调记录不存在')
            return redirect(url_for('index'))
        # 生成密钥
        secret_key = secrets.token_hex(16)
        callback.user_id = session['user_id']
        callback.secret_key = secret_key
        callback.is_confirmed = True
        db.session.commit()
        # 跳转回第三方应用
        separator = '&' if '?' in backurl else '?'
        return redirect(f"{backurl}{separator}uuid={uuid_val}")

    @app.route('/api/auth')
    def api_auth():
        """第三方应用通过 uuid 获取密钥"""
        uuid_val = request.args.get('uuid', '')
        callback = AuthCallback.query.filter_by(uuid=uuid_val, is_confirmed=True).first()
        if not callback:
            return jsonify({'error': '未找到已确认的授权记录'}), 404
        return jsonify({'uuid': callback.uuid, 'secret_key': callback.secret_key, 'user_id': callback.user_id})

    # ===== CUE Player =====
    @app.route('/player')
    def player():
        kn_dir = os.path.join(BASE_DIR, 'knplayer', 'CUE-Player', 'kn')
        index_path = os.path.join(kn_dir, 'index.html')
        with open(index_path, 'r', encoding='utf-8') as f:
            html = f.read()

        # 移除原有的 proxy 脚本（避免覆盖我们的劫持）
        import re
        # 移除从 "const originalFetch = window.fetch;" 到 "return originalOpen.apply(this, args);" 的 proxy 脚本
        html = re.sub(
            r'const originalFetch = window\.fetch;[\s\S]*?return originalOpen\.apply\(this, args\);',
            '// proxy script removed - handled by hijack script',
            html
        )

        # 注入劫持脚本（在 </head> 之前）
        hijack_script = '''
    <script>
    (function () {
        'use strict';
        const DEBUG = true;
        function log(...args) { if (DEBUG) console.log('[Hijack]', ...args); }

        let fileUrl = '';
        try { fileUrl = new URLSearchParams(location.search).get('file') || ''; } catch (_) { }

        const HIJACK_PATTERN = /creation\\.bcmcdn\\.com\\/922\\/user-files\\/[^/]+\\.bcmkn/;
        const WORK_DETAIL_PATTERN = /\\/neko\\/works\\/player\\/work-detail\\/\\d+/;
        const PROFILE_PATTERN = /\\/tiger\\/v3\\/web\\/accounts\\/profile/;
        const MANIFEST_PATTERN = /\\/manifest\\.json$/;

        function applyHijackRules(url) {
            if (typeof url !== 'string') return url;
            if (WORK_DETAIL_PATTERN.test(url) && fileUrl) {
                log('API劫持:', url, '→ 伪造作品详情');
                return 'data:application/json,' + encodeURIComponent(JSON.stringify({
                    work_id: 322407874, name: "播放器", user_id: 1716297772,
                    work_url: fileUrl, bcm_version: "0.27.2", work_type: 15,
                    preview_url: "https://creation.bcmcdn.com/922/user-files/d2ViXzIwMDJfMTcxNjI5Nzc3Ml8zMjI0MDc4NzRfMTc4NDE2MzYwMDAwMF9GZzhvQl8wR3gwUlJyT25XdTRyTFR1b3BYZnhl.jpeg",
                    update_time: 1784164681, create_time: 1783819708, work_classify: 0,
                    code: "", invte_url: "", invite_url_updated_at: 0, if_shared: 2,
                    stage_type: 2, published_status: 0, hardware_mode: 1, blink_mode: "",
                    fork_enable: 0, check_result: 1, if_default_cover: 1,
                    has_display_check_result: 1, include_ai_resource: 0, work_js_url: ""
                }));
            }
            if (PROFILE_PATTERN.test(url)) {
                log('API劫持:', url, '→ 伪造用户资料');
                return 'data:application/json,' + encodeURIComponent(JSON.stringify({
                    id: 1716297772, nickname: "danjvan",
                    avatar_url: "https://creation.bcmcdn.com//490/YW5kXzEwMDFfMTcxNjI5Nzc3Ml8wXzE3NTMyMzgwNTc2OTdfRHZsOXNlVlc=.jpg",
                    fullname: "", sex: 1, birthday: 0, qq: "269******",
                    description: "接广，求开源，好奇，交朋友请加QQ2690180230",
                    grade: 0, programmingBasics: 0, robotBasics: 0,
                    operatingSystem: [], parentalExpectation: [], parentalExpectationInput: "", grade_desc: "未选择"
                }));
            }
            if (MANIFEST_PATTERN.test(url)) {
                log('manifest劫持:', url);
                return 'data:application/json,' + encodeURIComponent(JSON.stringify({
                    short_name: "Neko", name: "Codemao Neko", icons: [],
                    start_url: ".", display: "standalone", theme_color: "#000000", background_color: "#ffffff"
                }));
            }
            return url;
        }

        log('已加载, file=', fileUrl || '(无)');

        // 劫持 fetch：先检查劫持规则，再走 proxy
        const _fetch = window.fetch;
        window.fetch = function (input, init) {
            let url = (typeof input === 'string') ? input : (input instanceof Request) ? input.url : String(input);
            const ruled = applyHijackRules(url);
            if (ruled !== url) {
                log('fetch劫持:', url, '→', ruled);
                if (typeof input === 'string') return _fetch.call(this, ruled, init);
                else return _fetch.call(this, new Request(ruled, init || input), init);
            }
            if (HIJACK_PATTERN.test(url) && fileUrl) {
                log('bcmkn劫持:', url, '→', fileUrl);
                if (typeof input === 'string') return _fetch.call(this, fileUrl, init);
                else return _fetch.call(this, new Request(fileUrl, init || input), init);
            }
            // 其他 codemao.cn 请求走 proxy
            if (typeof input === 'string' && input.includes('.codemao.cn')) {
                try {
                    const parsed = new URL(input);
                    input = `/proxy/${parsed.hostname}${parsed.pathname}${parsed.search}`;
                } catch (e) { }
            } else if (input instanceof Request) {
                const reqUrl = input.url;
                if (typeof reqUrl === 'string' && reqUrl.includes('.codemao.cn')) {
                    try {
                        const parsed = new URL(reqUrl);
                        const newUrl = `/proxy/${parsed.hostname}${parsed.pathname}${parsed.search}`;
                        const newInit = { ...init, ...input };
                        return _fetch.call(this, new Request(newUrl, newInit), init);
                    } catch (e) { }
                }
            }
            return _fetch.call(this, input, init);
        };

        // 劫持 XHR：先检查劫持规则，再走 proxy
        const _open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            if (typeof url === 'string') {
                const ruled = applyHijackRules(url);
                if (ruled !== url) { log('XHR劫持:', url, '→', ruled); url = ruled; }
                else if (HIJACK_PATTERN.test(url) && fileUrl) { log('bcmkn劫持:', url, '→', fileUrl); url = fileUrl; }
                else if (url.includes('.codemao.cn')) {
                    try {
                        const parsed = new URL(url);
                        url = `/proxy/${parsed.hostname}${parsed.pathname}${parsed.search}`;
                    } catch (e) { }
                }
            }
            return _open.call(this, method, url, ...rest);
        };
    })();
    </script>
'''
        html = html.replace('</head>', hijack_script + '\n</head>')
        return html

    @app.route('/manifest.json')
    def player_manifest():
        return jsonify({
            "short_name": "Neko",
            "name": "Codemao Neko",
            "icons": [],
            "start_url": ".",
            "display": "standalone",
            "theme_color": "#000000",
            "background_color": "#ffffff"
        })

    @app.route('/policy/<filename>')
    def policy_page(filename):
        if filename not in ('ys.md', 'user.md'):
            return 'Not Found', 404
        md_path = os.path.join(BASE_DIR, 'static', filename)
        if not os.path.isfile(md_path):
            return 'Not Found', 404
        with open(md_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return render_template('policy.html', title=filename.replace('.md', ''), content=content)

    @app.route('/player/<path:filename>')
    def player_static(filename):
        import mimetypes
        kn_dir = os.path.join(BASE_DIR, 'knplayer', 'CUE-Player', 'kn')
        file_path = os.path.join(kn_dir, filename)
        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            return send_file(file_path, mimetype=mime_type)
        return 'Not Found', 404

    # 处理 webpack chunk 加载的 /static/ 路径（从 player 的 static 目录提供）
    @app.route('/static/<path:filename>')
    def player_chunk_static(filename):
        import mimetypes
        # 优先从 player 的 static 目录查找
        kn_dir = os.path.join(BASE_DIR, 'knplayer', 'CUE-Player', 'kn', 'static')
        file_path = os.path.join(kn_dir, filename)
        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            return send_file(file_path, mimetype=mime_type)
        # 其次从项目 static 目录查找
        proj_static = os.path.join(BASE_DIR, 'static')
        file_path = os.path.join(proj_static, filename)
        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            return send_file(file_path, mimetype=mime_type)
        return 'Not Found', 404

    @app.route('/player/manifest.json')
    def player_manifest():
        return jsonify({
            "short_name": "Neko",
            "name": "Codemao Neko",
            "icons": [],
            "start_url": ".",
            "display": "standalone",
            "theme_color": "#000000",
            "background_color": "#ffffff"
        })

    @app.route('/proxy/<path:hostname>/<path:rest>')
    def proxy_request(hostname, rest):
        """代理请求到 codemao.cn"""
        import requests as req_lib
        # 模拟用户资料 API
        if 'accounts/profile' in rest or 'users/detail' in rest:
            return jsonify({
                "id": 1716297772,
                "nickname": "danjvan",
                "avatar_url": "https://creation.bcmcdn.com//490/YW5kXzEwMDFfMTcxNjI5Nzc3Ml8wXzE3NTMyMzgwNTc2OTdfRHZsOXNlVlc=.jpg",
                "fullname": "",
                "sex": 1,
                "birthday": 0,
                "qq": "269******",
                "description": "接广，求开源，好奇，交朋友请加QQ2690180230",
                "grade": 0,
                "programmingBasics": 0,
                "robotBasics": 0,
                "operatingSystem": [],
                "parentalExpectation": [],
                "parentalExpectationInput": "",
                "grade_desc": "未选择"
            })
        url = f"https://{hostname}/{rest}"
        try:
            resp = req_lib.get(url, params=request.args, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }, timeout=10)
            return resp.content, resp.status_code, {'Content-Type': resp.headers.get('Content-Type', 'application/octet-stream')}
        except Exception as e:
            return jsonify({'error': str(e)}), 502


def register_file_routes():
    @app.route('/myfiles')
    @login_required
    def myfiles():
        user = User.query.get(session['user_id'])

        # 支持通过URL参数切换空间
        switch_space_id = request.args.get('space_id', type=int)
        if switch_space_id:
            if user.is_admin:
                # 管理员可以直接切换到任何空间
                target_space = StorageSpace.query.get(switch_space_id)
                if target_space:
                    user.current_space_id = switch_space_id
                    db.session.commit()
            else:
                # 只读空间：所有用户自动拥有访问权限，无需手动分配
                target_space = StorageSpace.query.get(switch_space_id)
                if target_space and target_space.is_readonly:
                    user.current_space_id = switch_space_id
                    db.session.commit()
                else:
                    user_space = UserSpace.query.filter_by(user_id=user.id, space_id=switch_space_id).first()
                    if user_space:
                        user.current_space_id = switch_space_id
                        db.session.commit()

        if not user.current_space_id:
            flash('请先选择存储空间')
            return redirect(url_for('account'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('account'))

        user_folder = get_user_folder(user, space)
        file_entries = get_all_files_from_name_db(user_folder)

        # 搜索功能：按文件名过滤
        search_query = request.args.get('q', '').strip()
        if search_query:
            file_entries = [e for e in file_entries if search_query.lower() in e['original_name'].lower()]

        files = []
        for entry in file_entries:
            file_path = os.path.join(user_folder, entry['md5'])
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            files.append({
                'md5': entry['md5'],
                'original_name': entry['original_name'],
                'upload_time': entry['upload_time'],
                'file_size': file_size
            })

        # 计算当前空间使用情况
        user_used = 0
        if os.path.exists(user_folder):
            for f in os.listdir(user_folder):
                fp = os.path.join(user_folder, f)
                if os.path.isfile(fp):
                    user_used += os.path.getsize(fp)
        
        # 获取用户在该空间的配额
        if user.is_admin:
            space_limit = space.max_capacity
        else:
            user_space = UserSpace.query.filter_by(user_id=user.id, space_id=space.id).first()
            space_limit = user_space.max_capacity if user_space else space.max_capacity
        
        available = space_limit - user_used
        if available < 0:
            available = 0
        
        space_info = {
            'used': format_file_size(user_used),
            'max': format_file_size(space_limit),
            'percentage': round((user_used / space_limit * 100) if space_limit > 0 else 0, 2)
        }

        # 获取用户所有空间信息（包括所有只读空间）
        if user.is_admin:
            user_spaces = StorageSpace.query.all()
        else:
            # 普通用户：已分配的空间 + 所有只读空间
            assigned_spaces = user.spaces.all()
            readonly_spaces = StorageSpace.query.filter_by(is_readonly=True, is_active=True).all()
            # 合并去重
            space_ids = set(s.id for s in assigned_spaces)
            user_spaces = list(assigned_spaces)
            for s in readonly_spaces:
                if s.id not in space_ids:
                    user_spaces.append(s)
                    space_ids.add(s.id)
        
        spaces_info = []
        for s in user_spaces:
            if s.is_readonly:
                # 只读空间：直接使用空间路径
                s_folder = s.path
            else:
                s_folder = os.path.join(s.path, user.username)
            
            s_used = 0
            if os.path.exists(s_folder):
                for f in os.listdir(s_folder):
                    fp = os.path.join(s_folder, f)
                    if os.path.isfile(fp):
                        s_used += os.path.getsize(fp)
            
            # 获取用户在该空间的配额
            if user.is_admin:
                s_limit = s.max_capacity
            else:
                us = UserSpace.query.filter_by(user_id=user.id, space_id=s.id).first()
                s_limit = us.max_capacity if us else s.max_capacity
            
            s_available = s_limit - s_used
            if s_available < 0:
                s_available = 0
            s_percentage = round((s_used / s_limit * 100) if s_limit > 0 else 0, 2)
            spaces_info.append({
                'id': s.id,
                'name': s.name,
                'available': format_file_size(s_available),
                'percentage': s_percentage,
                'is_current': (s.id == user.current_space_id),
                'is_readonly': s.is_readonly
            })

        return render_template(
            'myfiles.html',
            files=files,
            current_space=space,
            space_info=space_info,
            spaces_info=spaces_info,
            user=user,
            search_query=search_query
        )

    @app.route('/upload', methods=['POST'])
    @login_required
    def upload():
        if 'file' not in request.files:
            flash('请选择文件')
            return redirect(url_for('myfiles'))

        file = request.files['file']
        if file.filename == '':
            flash('请选择文件')
            return redirect(url_for('myfiles'))

        # 安全检查：防止文件名路径遍历
        filename = os.path.basename(file.filename)
        if not filename or '..' in filename:
            flash('非法文件名')
            return redirect(url_for('myfiles'))

        user = User.query.get(session['user_id'])

        if not user.current_space_id:
            flash('请先选择存储空间')
            return redirect(url_for('myfiles'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('myfiles'))

        # 只读空间：仅管理员可上传
        if space.is_readonly and not user.is_admin:
            flash('只读空间仅管理员可上传文件')
            return redirect(url_for('myfiles'))

        file_data = file.read()
        file_size = len(file_data)

        # 安全检查：文件大小限制
        if file_size > app.config.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024):
            flash('文件过大')
            return redirect(url_for('myfiles'))

        # 计算当前用户在该空间的使用量（只读空间不限制个人容量）
        user_folder = get_user_folder(user, space)
        if not space.is_readonly:
            user_used = 0
            if os.path.exists(user_folder):
                for f in os.listdir(user_folder):
                    fp = os.path.join(user_folder, f)
                    if os.path.isfile(fp):
                        user_used += os.path.getsize(fp)
            
            # 获取用户在该空间的配额
            if user.is_admin:
                space_limit = space.max_capacity
            else:
                us = UserSpace.query.filter_by(user_id=user.id, space_id=space.id).first()
                space_limit = us.max_capacity if us else space.max_capacity
            
            if user_used + file_size > space_limit:
                flash('当前存储空间不足')
                return redirect(url_for('myfiles'))

            user_total_used = user.get_total_used()
            if user_total_used + file_size > user.max_total_storage:
                flash('您的总存储容量不足')
                return redirect(url_for('myfiles'))

        md5 = compute_file_md5_from_data(file_data)
        file_path = os.path.join(user_folder, md5)

        # 只读空间：如果文件已存在，自动重命名（加时间戳后缀）
        if space.is_readonly and os.path.exists(file_path):
            import time
            base_md5 = md5
            counter = 1
            while os.path.exists(file_path):
                md5 = f"{base_md5}_{counter}_{int(time.time())}"
                file_path = os.path.join(user_folder, md5)
                counter += 1

        with open(file_path, 'wb') as f:
            f.write(file_data)

        add_file_to_name_db(user_folder, md5, filename)

        file_record = FileRecord(
            user_id=user.id,
            space_id=space.id,
            filename=md5,
            original_filename=filename,
            file_size=file_size
        )
        db.session.add(file_record)
        db.session.commit()

        flash('上传成功')
        return redirect(url_for('myfiles'))

    @app.route('/download/<md5>')
    @login_required
    def download(md5):
        user = User.query.get(session['user_id'])

        # 安全检查：防止路径遍历
        if '..' in md5 or '/' in md5 or '\\' in md5:
            flash('非法文件名')
            return redirect(url_for('myfiles'))

        # 优先通过 FileRecord 查找文件（不依赖 current_space_id）
        file_record = FileRecord.query.filter_by(user_id=user.id, filename=md5).first()
        
        if file_record:
            space = StorageSpace.query.get(file_record.space_id)
            if space:
                user_folder = get_user_folder(user, space)
                file_path = os.path.join(user_folder, md5)
                
                real_path = os.path.realpath(file_path)
                real_folder = os.path.realpath(user_folder)
                if real_path.startswith(real_folder) and os.path.exists(file_path):
                    file_info = get_file_info_from_name_db(user_folder, md5)
                    if file_info:
                        response = send_file(
                            file_path,
                            as_attachment=True,
                            download_name=file_info['original_name']
                        )
                        response.headers['Access-Control-Allow-Origin'] = '*'
                        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
                        response.headers['Access-Control-Allow-Headers'] = '*'
                        return response

        # 回退：使用 current_space_id
        if not user.current_space_id:
            flash('文件不存在或请先选择存储空间')
            return redirect(url_for('myfiles'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('myfiles'))

        user_folder = get_user_folder(user, space)
        file_path = os.path.join(user_folder, md5)

        real_path = os.path.realpath(file_path)
        real_folder = os.path.realpath(user_folder)
        if not real_path.startswith(real_folder):
            flash('非法访问')
            return redirect(url_for('myfiles'))

        if not os.path.exists(file_path):
            # 只读空间：如果当前空间找不到，尝试所有只读空间
            readonly_spaces = StorageSpace.query.filter_by(is_readonly=True, is_active=True).all()
            for rs in readonly_spaces:
                rs_folder = rs.path
                rs_file = os.path.join(rs_folder, md5)
                rs_real = os.path.realpath(rs_file)
                rs_space_real = os.path.realpath(rs.path)
                if rs_real.startswith(rs_space_real) and os.path.exists(rs_file):
                    rs_info = get_file_info_from_name_db(rs_folder, md5)
                    if rs_info:
                        response = send_file(
                            rs_file,
                            as_attachment=True,
                            download_name=rs_info['original_name']
                        )
                        response.headers['Access-Control-Allow-Origin'] = '*'
                        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
                        response.headers['Access-Control-Allow-Headers'] = '*'
                        return response
            flash('文件不存在')
            return redirect(url_for('myfiles'))

        file_info = get_file_info_from_name_db(user_folder, md5)
        if not file_info:
            flash('文件信息不存在')
            return redirect(url_for('myfiles'))

        response = send_file(
            file_path,
            as_attachment=True,
            download_name=file_info['original_name']
        )
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = '*'
        return response

    @app.route('/public_download/<int:space_id>/<md5>')
    def public_download(space_id, md5):
        """免登录直链下载（支持跨域）"""
        # 安全检查：防止路径遍历
        if '..' in md5 or '/' in md5 or '\\' in md5:
            return '非法文件名', 400
        
        try:
            space_id = int(space_id)
        except (ValueError, TypeError):
            return '非法空间ID', 400

        space = StorageSpace.query.get(space_id)
        if not space or not space.is_active:
            return '空间不存在', 404

        # 获取空间根目录（只读空间直接用空间路径，普通空间需要遍历用户文件夹）
        if space.is_readonly:
            file_path = os.path.join(space.path, md5)
        else:
            # 普通空间：遍历所有有权限的用户文件夹查找文件
            file_path = None
            for user in space.users:
                user_folder = os.path.join(space.path, user.username)
                candidate = os.path.join(user_folder, md5)
                if os.path.exists(candidate):
                    file_path = candidate
                    break
            
            if not file_path:
                return '文件不存在', 404

        # 安全检查：确保文件在空间文件夹内
        real_path = os.path.realpath(file_path)
        real_space = os.path.realpath(space.path)
        if not real_path.startswith(real_space):
            return '非法访问', 403

        if not os.path.exists(file_path):
            return '文件不存在', 404

        # 从 name.db 获取原始文件名
        file_info = None
        if space.is_readonly:
            file_info = get_file_info_from_name_db(space.path, md5)
        else:
            for user in space.users:
                user_folder = os.path.join(space.path, user.username)
                file_info = get_file_info_from_name_db(user_folder, md5)
                if file_info:
                    break

        original_name = file_info['original_name'] if file_info else md5

        response = send_file(
            file_path,
            as_attachment=True,
            download_name=original_name
        )
        # 支持跨域下载
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = '*'
        response.headers['Cache-Control'] = 'public, max-age=31536000'  # 缓存1年
        return response

    @app.route('/generate_link/<md5>', methods=['POST'])
    @login_required
    def generate_link(md5):
        """生成永久直链"""
        user = User.query.get(session['user_id'])

        if not user.current_space_id:
            return jsonify({'success': False, 'message': '请先选择存储空间'})

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            return jsonify({'success': False, 'message': '存储空间不存在'})

        # 安全检查
        if '..' in md5 or '/' in md5 or '\\' in md5:
            return jsonify({'success': False, 'message': '非法文件名'})

        user_folder = get_user_folder(user, space)
        file_path = os.path.join(user_folder, md5)

        real_path = os.path.realpath(file_path)
        real_folder = os.path.realpath(user_folder)
        if not real_path.startswith(real_folder):
            return jsonify({'success': False, 'message': '非法访问'})

        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': '文件不存在'})

        # 生成直链
        link = request.url_root.rstrip('/') + f'/public_download/{space.id}/{md5}'
        return jsonify({'success': True, 'link': link})

    @app.route('/delete_file/<md5>', methods=['POST'])
    @login_required
    def delete_file(md5):
        user = User.query.get(session['user_id'])

        if not user.current_space_id:
            flash('请先选择存储空间')
            return redirect(url_for('myfiles'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('myfiles'))

        # 安全检查：防止路径遍历
        if '..' in md5 or '/' in md5 or '\\' in md5:
            flash('非法文件名')
            return redirect(url_for('myfiles'))

        # 只读空间：仅管理员可删除
        if space.is_readonly and not user.is_admin:
            flash('只读空间仅管理员可删除文件')
            return redirect(url_for('myfiles'))

        user_folder = get_user_folder(user, space)
        file_path = os.path.join(user_folder, md5)

        # 安全检查：确保文件在用户文件夹内
        real_path = os.path.realpath(file_path)
        real_folder = os.path.realpath(user_folder)
        if not real_path.startswith(real_folder):
            flash('非法访问')
            return redirect(url_for('myfiles'))

        if os.path.exists(file_path):
            os.remove(file_path)

        remove_file_from_name_db(user_folder, md5)

        file_record = FileRecord.query.filter_by(
            user_id=user.id, space_id=space.id, filename=md5
        ).first()
        if file_record:
            db.session.delete(file_record)
            db.session.commit()

        flash('删除成功')
        return redirect(url_for('myfiles'))

    @app.route('/rename_file/<md5>', methods=['POST'])
    @login_required
    def rename_file(md5):
        user = User.query.get(session['user_id'])
        new_name = request.form.get('new_name', '').strip()

        if not new_name:
            flash('文件名不能为空')
            return redirect(url_for('myfiles'))

        # 安全检查：防止路径遍历
        if '..' in new_name or '/' in new_name or '\\' in new_name:
            flash('非法文件名')
            return redirect(url_for('myfiles'))

        if not user.current_space_id:
            flash('请先选择存储空间')
            return redirect(url_for('myfiles'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('myfiles'))

        user_folder = get_user_folder(user, space)
        success = rename_file_in_name_db(user_folder, md5, new_name)
        if success:
            flash('重命名成功')
        else:
            flash('重命名失败')
        return redirect(url_for('myfiles'))

    @app.route('/toggle_preserve/<md5>', methods=['POST'])
    @login_required
    def toggle_preserve(md5):
        user = User.query.get(session['user_id'])

        if not user.current_space_id:
            flash('请先选择存储空间')
            return redirect(url_for('myfiles'))

        space = StorageSpace.query.get(user.current_space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('myfiles'))

        # 只读空间：仅管理员可标记保留
        if space.is_readonly and not user.is_admin:
            flash('只读空间仅管理员可操作')
            return redirect(url_for('myfiles'))

        user_folder = get_user_folder(user, space)
        success = toggle_preserve_file(user_folder, md5)
        if success:
            flash('操作成功')
        else:
            flash('操作失败')
        return redirect(url_for('myfiles'))

    @app.route('/switch_space', methods=['POST'])
    @login_required
    def switch_space():
        space_id = request.form.get('space_id')
        if not space_id:
            flash('请选择存储空间')
            return redirect(url_for('account'))
        
        try:
            space_id = int(space_id)
        except (ValueError, TypeError):
            flash('非法空间ID')
            return redirect(url_for('account'))
        
        user = User.query.get(session['user_id'])

        space = StorageSpace.query.get(space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('account'))

        if not user.is_admin:
            user_space = UserSpace.query.filter_by(user_id=user.id, space_id=space_id).first()
            if not user_space:
                flash('您没有该存储空间的权限')
                return redirect(url_for('account'))

        user.current_space_id = space_id
        db.session.commit()

        flash(f'已切换到存储空间：{space.name}')
        return redirect(url_for('myfiles'))


def compute_file_md5_from_data(data):
    import hashlib
    return hashlib.md5(data).hexdigest()


def register_account_routes():
    @app.route('/account')
    @login_required
    def account():
        user = User.query.get(session['user_id'])
        total_info = get_user_total_storage_info(user)

        if user.is_admin:
            user_spaces = StorageSpace.query.all()
        else:
            user_spaces = user.spaces.all()
        spaces_info = []
        for space in user_spaces:
            # 计算当前用户在该空间的使用量
            user_folder = os.path.join(space.path, user.username)
            user_used = 0
            if os.path.exists(user_folder):
                for f in os.listdir(user_folder):
                    fp = os.path.join(user_folder, f)
                    if os.path.isfile(fp):
                        user_used += os.path.getsize(fp)
            
            # 获取用户在该空间的配额
            if user.is_admin:
                space_limit = space.max_capacity
            else:
                us = UserSpace.query.filter_by(user_id=user.id, space_id=space.id).first()
                space_limit = us.max_capacity if us else space.max_capacity
            
            # 该空间对当前用户的可用容量
            available = space_limit - user_used
            if available < 0:
                available = 0
            
            percentage = (user_used / space_limit * 100) if space_limit > 0 else 0
            
            spaces_info.append({
                'id': space.id,
                'name': space.name,
                'used': format_file_size(user_used),
                'available': format_file_size(available),
                'max': format_file_size(space_limit),
                'percentage': round(percentage, 2),
                'is_current': (space.id == user.current_space_id)
            })

        return render_template(
            'account.html',
            user=user,
            total_info=total_info,
            spaces_info=spaces_info
        )

    @app.route('/send_pwd_code', methods=['POST'])
    @login_required
    def send_pwd_code():
        user = User.query.get(session['user_id'])
        code = str(random.randint(100000, 999999))
        
        # 清除旧验证码
        EmailVerification.query.filter_by(email=user.email, purpose='pwd_reset').delete()
        
        verification = EmailVerification(
            email=user.email,
            code=code,
            purpose='pwd_reset',
            created_at=datetime.datetime.now()
        )
        db.session.add(verification)
        db.session.commit()
        
        try:
            send_verification_email(user.email, code, 'CloudDrive 密码重置验证码',
                      f'您的验证码是：{code}，有效期10分钟。')
            return jsonify({'success': True, 'message': '验证码已发送'})
        except Exception as e:
            return jsonify({'success': False, 'message': '发送失败：' + str(e)})

    @app.route('/change_pwd_old', methods=['POST'])
    @login_required
    def change_pwd_old():
        user = User.query.get(session['user_id'])
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        if not old_password or not new_password:
            return jsonify({'success': False, 'message': '请填写完整信息'})
        
        if not check_password_hash(user.password, old_password):
            return jsonify({'success': False, 'message': '原密码错误'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': '密码长度不能少于6位'})
        
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '密码修改成功'})

    @app.route('/change_pwd_email', methods=['POST'])
    @login_required
    def change_pwd_email():
        user = User.query.get(session['user_id'])
        code = request.form.get('code')
        new_password = request.form.get('new_password')
        
        if not code or not new_password:
            return jsonify({'success': False, 'message': '请填写完整信息'})
        
        verification = EmailVerification.query.filter_by(
            email=user.email,
            code=code,
            purpose='pwd_reset'
        ).first()
        
        if not verification:
            return jsonify({'success': False, 'message': '验证码错误或已过期'})
        
        if (datetime.datetime.now() - verification.created_at).total_seconds() > 600:
            return jsonify({'success': False, 'message': '验证码已过期'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': '密码长度不能少于6位'})
        
        user.password = generate_password_hash(new_password)
        db.session.delete(verification)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '密码修改成功'})


def register_admin_routes():
    @app.route('/admin')
    @admin_required
    def admin_panel():
        page = request.args.get('page', 1, type=int)
        per_page = 20
        pagination = User.query.order_by(User.id.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        users = pagination.items
        spaces = StorageSpace.query.all()
        default_space = StorageSpace.query.filter_by(is_default=True).first()
        default_space_id = default_space.id if default_space else None
        return render_template('admin.html', 
            users=users, 
            pagination=pagination,
            spaces=spaces, 
            default_space_id=default_space_id
        )

    @app.route('/admin/add_space', methods=['POST'])
    @admin_required
    def admin_add_space():
        name = request.form.get('space_name')
        path = request.form.get('space_path')
        max_capacity = request.form.get('max_capacity')

        if not all([name, path, max_capacity]):
            flash('请填写完整信息')
            return redirect(url_for('admin_panel'))

        # 安全检查：防止路径遍历
        if '..' in path or name.strip() != name or len(name) > 100:
            flash('名称或路径不合法')
            return redirect(url_for('admin_panel'))

        try:
            # 支持小数GB，向下取整到字节
            max_capacity_bytes = int(float(max_capacity) * 1024 * 1024 * 1024)
        except:
            flash('容量格式错误')
            return redirect(url_for('admin_panel'))

        if not os.path.isabs(path):
            flash('路径必须是绝对路径')
            return redirect(url_for('admin_panel'))

        # 安全检查：规范化路径并验证
        path = os.path.normpath(path)
        if StorageSpace.query.filter_by(path=path).first():
            flash('该路径已存在')
            return redirect(url_for('admin_panel'))

        space = StorageSpace(
            name=name.strip(),
            path=path,
            max_capacity=max_capacity_bytes
        )
        db.session.add(space)
        db.session.commit()

        create_space_folder(space)

        flash('存储空间已添加')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/delete_space', methods=['POST'])
    @admin_required
    def admin_delete_space():
        space_id = request.form.get('space_id')
        if not space_id:
            flash('请选择要删除的空间')
            return redirect(url_for('admin_panel'))
        
        space = StorageSpace.query.get(space_id)
        if not space:
            flash('空间不存在')
            return redirect(url_for('admin_panel'))

        for user in space.users:
            user_folder = os.path.join(space.path, user.username)
            if os.path.exists(user_folder):
                shutil.rmtree(user_folder)

        FileRecord.query.filter_by(space_id=space_id).delete()
        UserSpace.query.filter_by(space_id=space_id).delete()

        users_with_this_space = User.query.filter_by(current_space_id=space_id).all()
        for u in users_with_this_space:
            u.current_space_id = None

        db.session.delete(space)
        db.session.commit()

        flash('存储空间已删除')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/set_default_space', methods=['POST'])
    @admin_required
    def admin_set_default_space():
        space_id = request.form.get('space_id')
        if not space_id:
            flash('请选择空间')
            return redirect(url_for('admin_panel'))
        
        space = StorageSpace.query.get(space_id)
        if not space:
            flash('空间不存在')
            return redirect(url_for('admin_panel'))

        # 取消其他空间的默认状态
        StorageSpace.query.update({'is_default': False})
        space.is_default = True
        db.session.commit()

        flash('默认空间已设置')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/toggle_readonly', methods=['POST'])
    @admin_required
    def admin_toggle_readonly():
        space_id = request.form.get('space_id')
        if not space_id:
            flash('请选择空间')
            return redirect(url_for('admin_panel'))
        
        space = StorageSpace.query.get(space_id)
        if not space:
            flash('空间不存在')
            return redirect(url_for('admin_panel'))

        space.is_readonly = not space.is_readonly
        db.session.commit()

        flash(f'空间已{"设为只读" if space.is_readonly else "取消只读"}')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/set_auto_assign', methods=['POST'])
    @admin_required
    def admin_set_auto_assign():
        space_id = request.form.get('space_id')
        auto_assign = request.form.get('auto_assign', type=int)
        if not space_id:
            flash('请选择空间')
            return redirect(url_for('admin_panel'))
        
        space = StorageSpace.query.get(space_id)
        if not space:
            flash('空间不存在')
            return redirect(url_for('admin_panel'))
        
        if space.is_readonly:
            flash('只读空间不支持设置自动分配')
            return redirect(url_for('admin_panel'))

        space.auto_assign = max(0, auto_assign)
        db.session.commit()

        if space.auto_assign > 0:
            flash(f'新用户注册将自动分配 {space.auto_assign}MB 空间')
        else:
            flash('新用户注册不再自动分配此空间')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/build_index', methods=['POST'])
    @admin_required
    def admin_build_index():
        space_id = request.form.get('space_id')
        if not space_id:
            return jsonify({'success': False, 'message': '请选择空间'})
        
        space = StorageSpace.query.get(space_id)
        if not space:
            return jsonify({'success': False, 'message': '空间不存在'})

        if not space.is_readonly:
            return jsonify({'success': False, 'message': '仅只读空间支持构建索引'})

        count = build_index_for_readonly_space(space.path)
        return jsonify({'success': True, 'message': f'索引构建完成，共索引了 {count} 个文件'})

    @app.route('/admin/assign_space', methods=['POST'])
    @admin_required
    def admin_assign_space():
        user_ids = request.form.getlist('user_ids')
        space_id = request.form.get('space_id')

        if not user_ids or not space_id:
            flash('请选择用户和存储空间')
            return redirect(url_for('admin_panel'))

        space = StorageSpace.query.get(space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user = User.query.get(uid)
            if user:
                existing = UserSpace.query.filter_by(user_id=uid, space_id=space_id).first()
                if not existing:
                    user_space = UserSpace(user_id=uid, space_id=space_id)
                    db.session.add(user_space)
                    count += 1

        db.session.commit()
        flash(f'已为 {count} 个用户分配存储空间')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/update_storage', methods=['POST'])
    @admin_required
    def admin_update_storage():
        user_ids = request.form.getlist('user_ids')
        max_total = request.form.get('max_total_storage')
        max_space = request.form.get('max_space_capacity')

        if not user_ids:
            flash('请选择用户')
            return redirect(url_for('admin_panel'))

        try:
            max_total_bytes = int(max_total) * 1024 * 1024 * 1024 if max_total else None
            max_space_bytes = int(max_space) * 1024 * 1024 * 1024 if max_space else None
        except:
            flash('容量格式错误')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user = User.query.get(uid)
            if user:
                if max_total_bytes is not None:
                    user.max_total_storage = max_total_bytes
                if max_space_bytes is not None:
                    for us in UserSpace.query.filter_by(user_id=uid).all():
                        us.max_capacity = max_space_bytes
                count += 1

        db.session.commit()
        flash(f'已更新 {count} 个用户的存储设置')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/delete_users', methods=['POST'])
    @admin_required
    def admin_delete_users():
        user_ids = request.form.getlist('user_ids')

        if not user_ids:
            flash('请选择用户')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user = User.query.get(uid)
            if user and not user.is_admin:
                for space in user.spaces:
                    user_folder = os.path.join(space.path, user.username)
                    if os.path.exists(user_folder):
                        shutil.rmtree(user_folder)

                FileRecord.query.filter_by(user_id=user.id).delete()
                UserSpace.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)
                count += 1

        db.session.commit()
        flash(f'已删除 {count} 个用户')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/clear_user_files', methods=['POST'])
    @admin_required
    def admin_clear_user_files():
        user_ids = request.form.getlist('user_ids')

        if not user_ids:
            flash('请选择用户')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user = User.query.get(uid)
            if user:
                for space in user.spaces:
                    user_folder = os.path.join(space.path, user.username)
                    if os.path.exists(user_folder):
                        shutil.rmtree(user_folder)
                        os.makedirs(user_folder, exist_ok=True)

                FileRecord.query.filter_by(user_id=user.id).delete()
                count += 1

        db.session.commit()
        flash(f'已清除 {count} 个用户的文件')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/toggle_admin', methods=['POST'])
    @admin_required
    def admin_toggle_admin():
        user_id = request.form.get('user_id')
        revoke_password = request.form.get('revoke_password', '')
        if not user_id:
            flash('请选择用户')
            return redirect(url_for('admin_panel'))
        
        user = User.query.get(user_id)
        if not user:
            flash('用户不存在')
            return redirect(url_for('admin_panel'))
        
        if user.is_admin:
            # 取消管理员：需要验证密码
            if revoke_password != ADMIN_REVOKE_PASSWORD:
                flash('取消管理员权限需要验证密码')
                return redirect(url_for('admin_panel'))
            user.is_admin = False
            db.session.commit()
            flash(f'用户 {user.username} 已取消管理员权限')
        else:
            user.is_admin = True
            db.session.commit()
            flash(f'用户 {user.username} 已设为管理员')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/remove_space_from_users', methods=['POST'])
    @admin_required
    def admin_remove_space_from_users():
        user_ids = request.form.getlist('user_ids')
        space_id = request.form.get('space_id')

        if not user_ids or not space_id:
            flash('请选择用户和存储空间')
            return redirect(url_for('admin_panel'))

        space = StorageSpace.query.get(space_id)
        if not space:
            flash('存储空间不存在')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user = User.query.get(uid)
            if user:
                user_space = UserSpace.query.filter_by(user_id=uid, space_id=space_id).first()
                if user_space:
                    if user.current_space_id == space_id:
                        other_space = UserSpace.query.filter(
                            UserSpace.user_id == uid,
                            UserSpace.space_id != space_id
                        ).first()
                        user.current_space_id = other_space.space_id if other_space else None

                    db.session.delete(user_space)
                    count += 1

        db.session.commit()
        flash(f'已从 {count} 个用户移除存储空间')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/user_spaces')
    @admin_required
    def admin_user_spaces():
        user_ids = request.args.get('user_ids', '').split(',')
        user_ids = [int(uid) for uid in user_ids if uid]
        
        all_spaces = StorageSpace.query.all()
        result = {'users': {}, 'all_spaces': [{'id': s.id, 'name': s.name} for s in all_spaces]}
        
        for uid in user_ids:
            user = User.query.get(uid)
            if not user:
                continue
            
            user_spaces = user.spaces.all()
            user_space_ids = [s.id for s in user_spaces]
            available_spaces = [s for s in all_spaces if s.id not in user_space_ids]
            
            spaces_data = []
            for space in user_spaces:
                user_folder = os.path.join(space.path, user.username)
                used = 0
                if os.path.exists(user_folder):
                    for f in os.listdir(user_folder):
                        fp = os.path.join(user_folder, f)
                        if os.path.isfile(fp):
                            used += os.path.getsize(fp)
                
                us = UserSpace.query.filter_by(user_id=uid, space_id=space.id).first()
                max_cap = us.max_capacity if us else space.max_capacity
                
                spaces_data.append({
                    'id': space.id,
                    'name': space.name,
                    'used': format_file_size(used),
                    'max': format_file_size(max_cap),
                    'max_bytes': max_cap
                })
            
            available_data = [{'id': s.id, 'name': s.name} for s in available_spaces]
            
            result['users'][str(uid)] = {
                'username': user.username,
                'spaces': spaces_data,
                'available_spaces': available_data
            }
        
        return jsonify(result)

    @app.route('/admin/update_space_capacity', methods=['POST'])
    @admin_required
    def admin_update_space_capacity():
        user_id = request.form.get('user_id')
        space_id = request.form.get('space_id')
        capacity = request.form.get('capacity')

        if not all([user_id, space_id, capacity]):
            flash('请填写完整信息')
            return redirect(url_for('admin_panel'))

        try:
            # 支持小数GB，向下取整到字节
            capacity_bytes = int(float(capacity) * 1024 * 1024 * 1024)
        except:
            flash('容量格式错误')
            return redirect(url_for('admin_panel'))

        user = User.query.get(user_id)
        space = StorageSpace.query.get(space_id)
        
        if not user or not space:
            flash('用户或空间不存在')
            return redirect(url_for('admin_panel'))

        user_space = UserSpace.query.filter_by(user_id=user_id, space_id=space_id).first()
        if not user_space:
            flash('用户没有该空间权限')
            return redirect(url_for('admin_panel'))

        user_space.max_capacity = capacity_bytes
        db.session.commit()

        flash('空间容量已更新')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/batch_update_space_capacity', methods=['POST'])
    @admin_required
    def admin_batch_update_space_capacity():
        user_ids = request.form.getlist('user_ids')
        space_id = request.form.get('space_id')
        capacity = request.form.get('capacity')

        if not user_ids or not space_id or not capacity:
            flash('请填写完整信息')
            return redirect(url_for('admin_panel'))

        try:
            # 支持小数GB，向下取整到字节
            capacity_bytes = int(float(capacity) * 1024 * 1024 * 1024)
        except:
            flash('容量格式错误')
            return redirect(url_for('admin_panel'))

        space = StorageSpace.query.get(space_id)
        if not space:
            flash('空间不存在')
            return redirect(url_for('admin_panel'))

        count = 0
        for uid in user_ids:
            uid = int(uid)
            user_space = UserSpace.query.filter_by(user_id=uid, space_id=space_id).first()
            if user_space:
                user_space.max_capacity = capacity_bytes
                count += 1

        db.session.commit()
        flash(f'已为 {count} 个用户更新空间容量')
        return redirect(url_for('admin_panel'))

    @app.route('/admin/remove_user_space', methods=['POST'])
    @admin_required
    def admin_remove_user_space():
        user_id = request.form.get('user_id')
        space_id = request.form.get('space_id')

        if not user_id or not space_id:
            flash('请选择用户和空间')
            return redirect(url_for('admin_panel'))

        user = User.query.get(user_id)
        space = StorageSpace.query.get(space_id)
        
        if not user or not space:
            flash('用户或空间不存在')
            return redirect(url_for('admin_panel'))

        user_space = UserSpace.query.filter_by(user_id=user_id, space_id=space_id).first()
        if user_space:
            if user.current_space_id == space_id:
                other_space = UserSpace.query.filter(
                    UserSpace.user_id == user_id,
                    UserSpace.space_id != space_id
                ).first()
                user.current_space_id = other_space.space_id if other_space else None

            user_folder = os.path.join(space.path, user.username)
            if os.path.exists(user_folder):
                shutil.rmtree(user_folder)
            
            FileRecord.query.filter_by(user_id=user_id, space_id=space_id).delete()
            db.session.delete(user_space)
            db.session.commit()

            flash('已移除用户空间权限')
        
        return redirect(url_for('admin_panel'))


def register_index_route():
    @app.route('/')
    @login_required
    def index():
        return redirect(url_for('myfiles'))

    @app.route('/favicon.ico')
    def favicon():
        return send_file(os.path.join(app.root_path, 'kecloud.png'), mimetype='image/png')