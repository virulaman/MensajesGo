from flask import Flask, render_template, request, redirect, url_for, session, flash
from replit import db
from datetime import datetime
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

def get_client_ip():
    """Obtener la IP del cliente"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def is_ip_blocked(ip_address):
    """Verificar si una dirección IP está bloqueada"""
    blocked_ips = db.get('blocked_ips', [])
    blocked_ip_list = [entry.get('ip') for entry in blocked_ips]
    return ip_address in blocked_ip_list

def log_user_activity(user_id, username, activity_type, ip_address):
    """Registrar actividad del usuario incluyendo intentos de login"""
    login_history = db.get('login_history', {})

    if user_id not in login_history:
        login_history[user_id] = []

    login_history[user_id].append({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': ip_address,
        'status': activity_type,
        'username': username
    })

    
    if len(login_history[user_id]) > 50:
        login_history[user_id] = login_history[user_id][-50:]

    db['login_history'] = login_history

def update_user_session(user_id, ip_address):
    """Actualizar información de sesión del usuario"""
    user_sessions = db.get('user_sessions', {})

    if user_id not in user_sessions:
        user_sessions[user_id] = {
            'login_count': 0,
            'first_login': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    user_sessions[user_id].update({
        'last_login': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_ip': ip_address,
        'login_count': user_sessions[user_id].get('login_count', 0) + 1
    })

    db['user_sessions'] = user_sessions

def get_replit_user_info():
    """Obtener información del usuario desde headers de Replit Auth"""
    user_id = request.headers.get('X-Replit-User-Id')
    username = request.headers.get('X-Replit-User-Name')
    profile_image = request.headers.get('X-Replit-User-Profile-Image')

    if user_id and username:
        return {
            'id': user_id,
            'username': username,
            'profile_image': profile_image
        }
    return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()

@app.route('/')
def home():
    client_ip = get_client_ip()

    if is_ip_blocked(client_ip):
        flash('Your IP address has been blocked. Contact the administrator.')
        return render_template('index.html'), 403

    replit_user = get_replit_user_info()
    if replit_user:
        session['user_id'] = replit_user['id']
        session['username'] = replit_user['username']
        session['is_replit_user'] = True

        users = db.get('users', {})
        if replit_user['username'] not in users:
            users[replit_user['username']] = {
                'id': replit_user['id'],
                'username': replit_user['username'],
                'password': '',
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'is_replit_user': True
            }
            db['users'] = users

        log_user_activity(replit_user['id'], replit_user['username'], 'replit_login', client_ip)
        update_user_session(replit_user['id'], client_ip)

        return redirect('/messages')

    if 'user_id' in session:
        return redirect('/messages')

    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Nombre de usuario y contraseña son requeridos')
            return render_template('register.html')

        users = db.get('users', {})
        if username in users:
            flash('El nombre de usuario ya existe')
            return render_template('register.html')

        user_id = str(len(users) + 1)
        users[username] = {
            'id': user_id,
            'username': username,
            'password': hash_password(password),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        db['users'] = users

        session['user_id'] = user_id
        session['username'] = username

        flash('¡Cuenta creada exitosamente!')
        return redirect('/messages')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = get_client_ip()

        if is_ip_blocked(client_ip):
            flash('Your IP address has been blocked. Contact the administrator.')
            return render_template('login.html'), 403

        users = db.get('users', {})
        banned_users = db.get('banned_users', [])

        if username in banned_users:
            flash('Tu cuenta ha sido banneada. Contacta al admin: LeonardoMateosoftware@gmail.com')
            return render_template('login.html')

        if username in users and verify_password(users[username]['password'], password):
            user_id = users[username]['id']
            session['user_id'] = user_id
            session['username'] = username

            log_user_activity(user_id, username, 'login', client_ip)
            update_user_session(user_id, client_ip)

            return redirect('/messages')
        else:
            if username:
                users = db.get('users', {})
                if username in users:
                    log_user_activity(users[username]['id'], username, 'failed_login', client_ip)
            flash('Nombre de usuario o contraseña inválidos')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión')
    return redirect('/')

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect('/login')

    users = db.get('users', {})
    user_list = [{'username': username, 'id': user_data['id']} 
                 for username, user_data in users.items() 
                 if username != session['username']]

    all_messages = db.get('messages', [])
    blocks = db.get('blocks', {})

    user_messages = []
    for msg in all_messages:
        if msg.get('recipient_id') == session['user_id'] or msg.get('user_id') == session['user_id']:
            if session['user_id'] in blocks:
                if msg.get('user_id') in blocks[session['user_id']]:
                    continue
            user_messages.append(msg)

    return render_template('messages.html', messages=user_messages, 
                          user_name=session['username'], users=user_list)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect('/login')

    message_text = request.form.get('message')
    recipient_id = request.form.get('recipient_id')

    if not message_text:
        flash('El mensaje no puede estar vacío')
        return redirect('/messages')

    if not recipient_id:
        flash('Por favor selecciona un usuario para enviar el mensaje')
        return redirect('/messages')

    users = db.get('users', {})
    recipient_username = None
    for username, user_data in users.items():
        if user_data['id'] == recipient_id:
            recipient_username = username
            break

    blocks = db.get('blocks', {})
    if recipient_id in blocks and session['user_id'] in blocks[recipient_id]:
        flash(f'No puedes enviar mensajes a {recipient_username}')
        return redirect('/messages')

    message = {
        'id': len(db.get('messages', [])) + 1,
        'user_id': session['user_id'],
        'user_name': session['username'],
        'recipient_id': recipient_id,
        'recipient_name': recipient_username,
        'text': message_text,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    messages = db.get('messages', [])
    messages.append(message)
    db['messages'] = messages

    flash(f'¡Mensaje enviado a {recipient_username}!')
    return redirect('/messages')

@app.route('/report_user', methods=['POST'])
def report_user():
    if 'user_id' not in session:
        return redirect('/login')

    reported_user = request.form.get('reported_user')
    reason = request.form.get('reason')
    reported_message = request.form.get('reported_message')
    reported_timestamp = request.form.get('reported_timestamp')

    if not reported_user or not reason:
        flash('Por favor proporciona tanto el nombre de usuario como la razón')
        return redirect('/messages')

    report = {
        'reported_by': session['username'],
        'reported_user': reported_user,
        'reason': reason,
        'reported_message': reported_message,
        'message_timestamp': reported_timestamp,
        'report_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    reports = db.get('reports', [])
    reports.append(report)
    db['reports'] = reports

    flash(f'Usuario {reported_user} ha sido reportado')
    return redirect('/messages')

@app.route('/block_user', methods=['POST'])
def block_user():
    if 'user_id' not in session:
        return redirect('/login')

    block_username = request.form.get('block_username')

    if not block_username:
        flash('Por favor proporciona el nombre de usuario a bloquear')
        return redirect('/messages')

    users = db.get('users', {})
    block_user_id = None
    for username, user_data in users.items():
        if username == block_username:
            block_user_id = user_data['id']
            break

    if not block_user_id:
        flash('Usuario no encontrado')
        return redirect('/messages')

    if block_user_id == session['user_id']:
        flash('No puedes bloquearte a ti mismo')
        return redirect('/messages')

    blocks = db.get('blocks', {})
    if session['user_id'] not in blocks:
        blocks[session['user_id']] = []

    if block_user_id not in blocks[session['user_id']]:
        blocks[session['user_id']].append(block_user_id)
        db['blocks'] = blocks
        flash(f'Usuario {block_username} ha sido bloqueado')
    else:
        flash(f'Usuario {block_username} ya está bloqueado')

    return redirect('/messages')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
