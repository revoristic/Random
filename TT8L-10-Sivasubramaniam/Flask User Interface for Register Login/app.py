from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'RegisterLogin'
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key= True)
    email = db.Column(db.String(90), nullable=False, unique=True)
    username = db.Column(db.String(30),  nullable=False, unique=True)
    password = db.Column(db.String(90), nullable=False)
    is_lecturer= db.Column(db.Boolean(), default=False)

# Creates all tables from db.Model
with app.app_context():
    db.create_all()

@app.route('/')
def home():
           return render_template('home.html')

@app.route('/register', methods=['GET', 'POST']) #leading to register page after click localhost5000/register
def register():
    message = "Please enter your details to create an account."
    
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('psw')
        password_reconfirm = request.form.get('psw-reconfirm')
        
        email_split = email.split('@') #split email to get domain
        domain = email_split[1]
        if domain!="mmu.edu.my" and domain!="student.mmu.edu.my":
            message = 'Not MMU Email'
            return render_template('register.html',message=message)
        
        if password != password_reconfirm: #password and password reconfirm must be same
            message = 'Passwords do not match!'
            return render_template('register.html', message=message)

        existing_user_email = User.query.filter_by(email=email).first()# If user is already register, message is displayed
        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_email or existing_user_username:
            message = 'Username or email already exists!'
            return render_template('register.html', message=message)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') #make the password hasshed
        if(domain=="mmu.edu.my"):
            new_user = User(email=email, username=username, password=hashed_password, is_lecturer=True)
        else:
            new_user = User(email=email, username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login')) #redirect from register to login page

    return render_template('register.html', message=message)

@app.route('/lecturer', methods=['GET', 'POST']) #define lecturer.html
def lecturer():
    return render_template('lecturer.html')

@app.route('/student', methods=['GET', 'POST'])
def student():
    return render_template('student.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    message = "Please enter your login details."
    
    if request.method == 'POST':
        username_email = request.form.get('username_email')
        password = request.form.get('psw')
        
        user = User.query.filter((User.username == username_email) | (User.email == username_email)).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.is_lecturer==True:
                return redirect(url_for('lecturer')) #will fill in this later with my friend's html link
            else :
                return redirect(url_for('student')) #will fill in this later with my friend's html link
        else:
            message = 'Invalid username/email or password!' #if username or email or password incorrect return to login page
            return render_template('login.html', message=message)
    
    return render_template('login.html', message=message)

if __name__ == '__main__': #running the localhost5000 for Register and Login
    app.run(debug=True)
