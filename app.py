# main_app/app.py

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import re
from datetime import datetime

# --- App Configuration ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)
db_path = os.path.join(instance_path, 'clubfusion.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SECRET_KEY'] = 'a_very_long_and_random_secret_key_change_me'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Association Tables ---
club_membership = db.Table('club_membership',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('club_id', db.Integer, db.ForeignKey('club.id'), primary_key=True)
)

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    clubs = db.relationship('Club', secondary=club_membership, backref=db.backref('members', lazy='dynamic'))
    attendance = db.relationship('Attendance', backref='attendee', lazy='dynamic')

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manager = db.relationship('User', backref=db.backref('managed_clubs', lazy=True))
    events = db.relationship('Event', backref='club', lazy=True, cascade="all, delete-orphan")

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    details = db.Column(db.Text, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    attendances = db.relationship('Attendance', backref='event', lazy='dynamic', cascade="all, delete-orphan")

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(10), nullable=False, default='Absent') # Present, Absent, Excused
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

def assign_role_from_email(email):
    if 'admin' in email.lower(): return 'admin'
    if 'teacher' in email.lower(): return 'teacher'
    if 'manager' in email.lower(): return 'manager'
    return 'student'

def seed_database():
    if User.query.first() is None:
        print("Database is empty. Seeding...")
        admin_pass = bcrypt.generate_password_hash('AdminPassword1!').decode('utf-8')
        admin_user = User(username='admin', email='default.admin@clubfusion.com', password=admin_pass, role='admin')
        manager1_pass = bcrypt.generate_password_hash('ManagerPass1!').decode('utf-8')
        manager1 = User(username='ChessMaster', email='chess.manager@clubfusion.com', password=manager1_pass, role='manager')
        manager2_pass = bcrypt.generate_password_hash('ManagerPass2!').decode('utf-8')
        manager2 = User(username='TechGuru', email='tech.manager@clubfusion.com', password=manager2_pass, role='manager')
        db.session.add_all([admin_user, manager1, manager2])
        db.session.commit()
        club1 = Club(name="Knights of the Round Table", description="A club for chess enthusiasts.", manager_id=manager1.id)
        club2 = Club(name="Code & Coffee", description="Exploring technology.", manager_id=manager2.id)
        db.session.add_all([club1, club2])
        db.session.commit()
        print("Seeding complete.")


# --- Authentication Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, email, password = request.form.get('username'), request.form.get('email'), request.form.get('password')
        error = None
        if len(password) < 8: error = 'Password must be at least 8 characters long.'
        elif not re.search("[a-z]", password): error = 'Password must contain a lowercase letter.'
        elif not re.search("[A-Z]", password): error = 'Password must contain an uppercase letter.'
        elif not re.search("[0-9]", password): error = 'Password must contain a number.'
        elif not re.search("[!@#$%^&*()_+-=]", password): error = 'Password must contain a special character.'
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            error = 'Username or email already exists.'
        
        if error:
            flash(error, 'danger')
            return redirect(url_for('register'))
        
        user_role = assign_role_from_email(email)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=user_role)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Main Application Routes ---
@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html')

@app.route('/clubs')
@login_required
def clubs():
    all_clubs = Club.query.order_by(Club.name).all()
    joined_club_ids = [club.id for club in current_user.clubs]
    return render_template('clubs.html', all_clubs=all_clubs, joined_club_ids=joined_club_ids)

@app.route('/create_club', methods=['GET', 'POST'])
@login_required
def create_club():
    if current_user.role not in ['manager', 'admin']:
        flash('You do not have permission to create a club.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name, description = request.form.get('name'), request.form.get('description')
        if Club.query.filter_by(name=name).first():
            flash('A club with this name already exists.', 'danger')
        else:
            new_club = Club(name=name, description=description, manager_id=current_user.id)
            db.session.add(new_club)
            db.session.commit()
            flash(f'Club "{name}" created!', 'success')
            return redirect(url_for('clubs'))
    return render_template('create_club.html')

@app.route('/join_club/<int:club_id>', methods=['POST'])
@login_required
def join_club(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user not in club.members:
        current_user.clubs.append(club)
        db.session.commit()
        flash(f'You have joined {club.name}!', 'success')
    return redirect(url_for('clubs'))

@app.route('/leave_club/<int:club_id>', methods=['POST'])
@login_required
def leave_club(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user in club.members:
        current_user.clubs.remove(club)
        db.session.commit()
        flash(f'You have left {club.name}.', 'success')
    return redirect(url_for('clubs'))

@app.route('/delete_club/<int:club_id>', methods=['POST'])
@login_required
def delete_club(club_id):
    if current_user.role != 'admin': return redirect(url_for('clubs'))
    club = Club.query.get_or_404(club_id)
    db.session.delete(club)
    db.session.commit()
    flash(f'Club "{club.name}" has been deleted.', 'success')
    return redirect(url_for('clubs'))

@app.route('/manage_club/<int:club_id>', methods=['GET', 'POST'])
@login_required
def manage_club(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        flash('You do not have permission to manage this club.', 'danger')
        return redirect(url_for('clubs'))
    if request.method == 'POST':
        club.name = request.form.get('name')
        club.description = request.form.get('description')
        db.session.commit()
        flash('Club details updated!', 'success')
        return redirect(url_for('manage_club', club_id=club.id))
    return render_template('manage_club.html', club=club)

@app.route('/remove_member/<int:club_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member(club_id, user_id):
    club = Club.query.get_or_404(club_id)
    user = User.query.get_or_404(user_id)
    if current_user.id != club.manager_id and current_user.role != 'admin':
        return redirect(url_for('clubs'))
    if user in club.members:
        club.members.remove(user)
        db.session.commit()
        flash(f'{user.username} has been removed from the club.', 'success')
    return redirect(url_for('manage_club', club_id=club.id))

@app.route('/create_event/<int:club_id>', methods=['POST'])
@login_required
def create_event(club_id):
    club = Club.query.get_or_404(club_id)
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        return redirect(url_for('clubs'))
    title, details = request.form.get('title'), request.form.get('details')
    start_time_str, end_time_str = request.form.get('start_time'), request.form.get('end_time')
    new_event = Event(
        title=title, details=details,
        start_time=datetime.fromisoformat(start_time_str),
        end_time=datetime.fromisoformat(end_time_str),
        club_id=club.id
    )
    db.session.add(new_event)
    db.session.commit()
    flash('New event created!', 'success')
    return redirect(url_for('manage_club', club_id=club.id))


@app.route('/manage_event/<int:event_id>')
@login_required
def manage_event(event_id):
    event = Event.query.get_or_404(event_id)
    club = event.club
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        flash('You do not have permission to manage this event.', 'danger')
        return redirect(url_for('clubs'))
    attendance_records = {att.user_id: att.status for att in event.attendances}
    return render_template('manage_event.html', event=event, club=club, attendance_records=attendance_records)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    club = event.club
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        return redirect(url_for('clubs'))
    db.session.delete(event)
    db.session.commit()
    flash(f'Event "{event.title}" has been deleted.', 'success')
    return redirect(url_for('manage_club', club_id=club.id))
    
@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    club = event.club
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        flash('You do not have permission to edit this event.', 'danger')
        return redirect(url_for('manage_club', club_id=club.id))

    if request.method == 'POST':
        event.title = request.form.get('title')
        event.details = request.form.get('details')
        event.start_time = datetime.fromisoformat(request.form.get('start_time'))
        event.end_time = datetime.fromisoformat(request.form.get('end_time'))
        db.session.commit()
        flash('Event details have been updated!', 'success')
        return redirect(url_for('manage_event', event_id=event.id))
    
    return render_template('edit_event.html', event=event)


@app.route('/update_attendance/<int:event_id>', methods=['POST'])
@login_required
def update_attendance(event_id):
    event = Event.query.get_or_404(event_id)
    club = event.club
    if current_user.id != club.manager_id and current_user.role not in ['admin', 'teacher']:
        return redirect(url_for('clubs'))
    for user_id_str, status in request.form.items():
        if user_id_str.startswith('status_'):
            user_id = int(user_id_str.replace('status_', ''))
            attendance_record = Attendance.query.filter_by(event_id=event_id, user_id=user_id).first()
            if attendance_record:
                attendance_record.status = status
            else:
                new_attendance = Attendance(event_id=event_id, user_id=user_id, status=status)
                db.session.add(new_attendance)
    db.session.commit()
    flash('Attendance has been updated successfully!', 'success')
    return redirect(url_for('manage_event', event_id=event_id))

# --- Calendar and API Routes ---
@app.route('/calendar')
@login_required
def calendar(): return render_template('calendar.html')

@app.route('/api/events')
@login_required
def api_events():
    events = Event.query.all()
    event_list = [{'title': f"{event.title} ({event.club.name})", 'start': event.start_time.isoformat(), 'end': event.end_time.isoformat(), 'url': url_for('manage_event', event_id=event.id)} for event in events]
    return jsonify(event_list)

# --- Main Execution ---
with app.app_context():
    db.create_all()
    seed_database()

if __name__ == '__main__':
    app.run(debug=True)