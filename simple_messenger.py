from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import pytz

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messenger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Настройка временной зоны
KIEV_TZ = pytz.timezone('Europe/Kiev')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chats'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return 'Username already exists', 400
            
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('chats'))
        
        error = 'Invalid username or password. Please try again or register.'
        
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chats', methods=['GET', 'POST'])
def chats():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        other_username = request.form['other_user']
        other_user = User.query.filter_by(username=other_username).first()
        
        if other_user and other_user.id != user_id:
            existing_chat = Chat.query.filter(
                ((Chat.user1_id == user_id) & (Chat.user2_id == other_user.id)) |
                ((Chat.user1_id == other_user.id) & (Chat.user2_id == user_id))
            ).first()
            
            if not existing_chat:
                new_chat = Chat(user1_id=user_id, user2_id=other_user.id)
                db.session.add(new_chat)
                db.session.commit()
                
        return redirect(url_for('chats'))

    user_chats = Chat.query.filter(
        (Chat.user1_id == user_id) | (Chat.user2_id == user_id)
    ).all()

    chat_list = []
    for chat in user_chats:
        other_id = chat.user1_id if chat.user2_id == user_id else chat.user2_id
        other_user = User.query.get(other_id)
        chat_list.append({
            'chat_id': chat.id,
            'username': other_user.username
        })

    return render_template('chats.html', chats=chat_list)

@app.route('/chat/<int:chat_id>', methods=['GET', 'POST'])
def chat(chat_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    chat = Chat.query.get(chat_id)
    user_id = session['user_id']
    
    if not chat or user_id not in [chat.user1_id, chat.user2_id]:
        return 'Access denied', 403

    # Получаем информацию о пользователях
    current_user = User.query.get(user_id).username
    other_id = chat.user1_id if chat.user2_id == user_id else chat.user2_id
    other_user = User.query.get(other_id).username

    if request.method == 'POST':
        text = request.form['text'].strip()
        if text:
            new_message = Message(
                chat_id=chat.id,
                sender_id=user_id,
                text=text
            )
            db.session.add(new_message)
            db.session.commit()
        return redirect(url_for('chat', chat_id=chat.id))

    # Получаем сообщения с правильным временем
    messages = Message.query.filter_by(chat_id=chat.id).order_by(
        Message.timestamp.asc()
    ).all()
    
    message_list = []
    for msg in messages:
        try:
            kiev_time = msg.timestamp.replace(tzinfo=timezone.utc).astimezone(KIEV_TZ)
            time_str = kiev_time.strftime('%H:%M (%d.%m)')
        except Exception as e:
            print(f"Error formatting time: {e}")
            time_str = "--:-- (--.--)"
            
        message_list.append({
            'sender': User.query.get(msg.sender_id).username,
            'text': msg.text,
            'time': time_str,
            'is_current_user': msg.sender_id == user_id
        })
    
    return render_template(
        'chat.html',
        messages=message_list,
        chat_id=chat.id,
        current_user=current_user,
        other_user=other_user
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
