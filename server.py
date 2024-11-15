from flask import Flask, render_template, request, session, redirect, url_for, flash, send_from_directory
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['BCRYPT_LOG_ROUNDS'] = 12  # Число раундов для хэширования паролей
app.config['UPLOAD_FOLDER'] = 'uploads'  # Папка для сохранения загруженных файлов
socketio = SocketIO(app)

# Вспомогательная функция для хэширования пароля
def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

# Вспомогательная функция для проверки пароля
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)

# В-памяти база данных пользователей
users = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка, зарегистрирован ли пользователь
        if username in users:
            # Проверка пароля
            if check_password(password, users[username]):
                session['username'] = username
                return redirect(url_for('chat'))
            else:
                flash('Неверный пароль. Пожалуйста, попробуйте еще раз.')
        else:
            # Регистрация нового пользователя
            users[username] = hash_password(password)
            session['username'] = username
            return redirect(url_for('chat'))

    return render_template('index.html')

@app.route('/chat')
def chat():
    username = session.get('username')
    if not username:
        return redirect(url_for('index'))

    return render_template('chat.html', username=username)

@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    message = data['message']
    emit('receive_message', {'username': username, 'message': message}, broadcast=True)

@app.route('/private-chat/<username>')
def private_chat(username):
    if session.get('username') == username:
        flash('Вы не можете отправлять сообщения себе.')
        return redirect(url_for('chat'))

    return render_template('private_chat.html', username=username)
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Нет файла для загрузки.')
        return redirect(url_for('chat'))

    file = request.files['file']
    if file.filename == '':
        flash('Имя файла не должно быть пустым.')
        return redirect(url_for('chat'))

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('Файл успешно загружен!')

    return redirect(url_for('chat'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=80, debug=True, use_reloader=False)
