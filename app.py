from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_123!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Reagent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=False)
    purity = db.Column(db.String(50))
    standard = db.Column(db.String(50))
    method = db.Column(db.String(50))
    batch_number = db.Column(db.String(50))
    production_date = db.Column(db.DateTime)
    arrival_date = db.Column(db.DateTime, default=datetime.utcnow)
    manufacturer = db.Column(db.String(100))
    warning_period = db.Column(db.Integer)  # в днях

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reagent_id = db.Column(db.Integer, db.ForeignKey('reagent.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    quantity_change = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    details = db.Column(db.String(200))

    user = db.relationship('User', backref=db.backref('actions', lazy=True))
    reagent = db.relationship('Reagent', backref=db.backref('logs', lazy=True))

# Фильтр для форматирования даты в шаблонах
@app.template_filter('datetime')
def format_datetime(value):
    if value is None:
        return ""
    return value.strftime('%Y-%m-%d %H:%M')

# Инициализация базы данных
def init_db():
    with app.app_context():
        db.create_all()
        # Создаем администратора по умолчанию
        if not User.query.filter_by(username='user').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin'),
                is_admin=True
            )
            user = User(
                username='user',
                password=generate_password_hash('user'),
                is_admin=False
            )
            db.session.add(admin)
            db.session.add(user)
            db.session.commit()
            
            # Добавляем тестовый реактив
            test_reagent = Reagent(
                name="Тестовый реактив",
                expiry_date=datetime(2025, 12, 31),
                quantity=100.0,
                unit="г",
                purity="99.9%",
                standard="ISO 9001",
                method="Аналитическая",
                batch_number="TEST-001",
                production_date=datetime(2024, 1, 15),
                manufacturer="Test Chemicals",
                warning_period=30
            )
            db.session.add(test_reagent)
            db.session.commit()
        print("База данных инициализирована")

@app.before_request
def before_request():
    g.current_user = None
    if 'user_id' in session:
        g.current_user = User.query.get(session['user_id'])

# Система аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Вы успешно вошли в систему', 'success')
            return redirect(url_for('reagents'))  # Перенаправляем сразу на страницу реактивов
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')

# Управление пользователями
@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash('Доступ запрещен: требуется права администратора', 'danger')
        return redirect(url_for('index'))
    
    all_users = User.query.all()
    return render_template('users.html', users=all_users, current_user=current_user)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():  # Имя функции должно совпадать с url_for('add_user')
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash('Требуются права администратора', 'danger')
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'danger')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь добавлен', 'success')
            return redirect(url_for('users'))
    
    return render_template('add_user.html')  # Убедитесь, что шаблон существует

@app.route('/delete_user/<int:id>')
def delete_user(id):  # Обратите внимание на имя функции - должно совпадать с url_for('delete_user')
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash('Требуются права администратора', 'danger')
        return redirect(url_for('users'))
    
    user_to_delete = User.query.get_or_404(id)
    
    # Запрещаем удаление самого себя
    if user_to_delete.id == current_user.id:
        flash('Нельзя удалить самого себя', 'danger')
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('Пользователь удален', 'success')
    
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

# Главная страница (перенаправление на учет реактивов)
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('reagents'))  # Перенаправляем на страницу реактивов

# Управление реактивами
@app.route('/reagents')
def reagents():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Устанавливаем временную зону (например, для Москвы)
    local_tz = pytz.timezone('Europe/Moscow')
    utc = pytz.utc

    all_reagents = Reagent.query.order_by(Reagent.expiry_date).all()

    # Получаем текущее время в локальной временной зоне
    now_local = datetime.now(local_tz)
    
    return render_template('reagents.html', 
                         reagents=all_reagents,
                         now_local=now_local,
                         local_tz=local_tz,
                         utc=utc)


@app.route('/add_reagent', methods=['GET', 'POST'])
def add_reagent():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Сбор данных из формы
        new_reagent = Reagent(
            name=request.form['name'],
            expiry_date=datetime.strptime(request.form['expiry_date'], '%Y-%m-%d'),
            quantity=float(request.form['quantity']),
            unit=request.form['unit'],
            purity=request.form['purity'],
            standard=request.form['standard'],
            method=request.form['method'],
            batch_number=request.form['batch_number'],
            production_date=datetime.strptime(request.form['production_date'], '%Y-%m-%d'),
            manufacturer=request.form['manufacturer'],
            warning_period=int(request.form['warning_period'])
        )
        
        db.session.add(new_reagent)
        db.session.commit()
        
        # Логирование действия
        log = ActionLog(
            user_id=session['user_id'],
            reagent_id=new_reagent.id,
            action='Добавление',
            quantity_change=new_reagent.quantity,
            details=f"Добавлен новый реактив: {new_reagent.name}"
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Реактив успешно добавлен', 'success')
        return redirect(url_for('reagents'))
    
    return render_template('reagent_form.html')

@app.route('/edit_reagent/<int:id>', methods=['GET', 'POST'])
def edit_reagent(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    reagent = Reagent.query.get_or_404(id)
    
    if request.method == 'POST':
        # Сохраняем старые значения для логирования
        old_quantity = reagent.quantity
        
        # Обновляем данные
        reagent.name = request.form['name']
        reagent.expiry_date = datetime.strptime(request.form['expiry_date'], '%Y-%m-%d')
        reagent.quantity = round(float(request.form['quantity']), 3)
        reagent.unit = request.form['unit']
        reagent.purity = request.form['purity']
        reagent.standard = request.form['standard']
        reagent.method = request.form['method']
        reagent.batch_number = request.form['batch_number']
        reagent.production_date = datetime.strptime(request.form['production_date'], '%Y-%m-%d')
        reagent.manufacturer = request.form['manufacturer']
        reagent.warning_period = int(request.form['warning_period'])
        
        db.session.commit()
        
        # Логирование изменения
        quantity_change = reagent.quantity - old_quantity
        log = ActionLog(
            user_id=session['user_id'],
            reagent_id=reagent.id,
            action='Изменение',
            quantity_change=quantity_change,
            details=f"Изменен реактив: {reagent.name}"
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Реактив успешно обновлен', 'success')
        return redirect(url_for('reagents'))
    
    return render_template('reagent_form.html', reagent=reagent)

@app.route('/delete_reagent/<int:id>')
def delete_reagent(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    reagent = Reagent.query.get_or_404(id)
    reagent_name = reagent.name
    
    # Логирование перед удалением
    log = ActionLog(
        user_id=session['user_id'],
        reagent_id=reagent.id,
        action='Удаление',
        quantity_change=-reagent.quantity,
        details=f"Удален реактив: {reagent_name}"
    )
    db.session.add(log)
    
    db.session.delete(reagent)
    db.session.commit()
    
    flash(f'Реактив "{reagent_name}" успешно удален', 'success')
    return redirect(url_for('reagents'))

# Журнал действий
@app.route('/action_log')
def action_log():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash('Доступ запрещен: требуется права администратора', 'danger')
        return redirect(url_for('index'))
    
    logs = ActionLog.query.order_by(ActionLog.timestamp.desc()).all()
    return render_template('action_log.html', logs=logs)



if __name__ == '__main__':
    init_db()  # Инициализация БД при запуске
    app.run(debug=True)