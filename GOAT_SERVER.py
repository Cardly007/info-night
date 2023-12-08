from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_wtf import FlaskForm
from flask_jwt_extended import jwt_required, current_user
from flask_admin import Admin,AdminIndexView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin.actions import action



from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_admin.contrib.sqla import ModelView

from passlib.hash import sha256_crypt  # Importez la méthode de hachage SHA-256 de Passlib
from functools import wraps
import os

# Configuration de l'application Flask
app = Flask(__name__)
app.secret_key = 'GOAT_AND_CO'
app.config['SECRET_KEY'] = 'JUST_GOAT'

# Configuration de la base de données
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'goat.db')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
#admin = Admin(app, name='Admin', template_mode='bootstrap3')


'''
creation de la BD
flask db init  # Initialisez les migrations
flask db migrate -m "Initial migration."  # Créez une migration
flask db upgrade  # Appliquez la migration pour créer la base de données

'''
# Initialisation du gestionnaire de connexion
login_manager = LoginManager()
login_manager.init_app(app)



# Définition du modèle goat pour la base de données
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class MyAdminView(AdminIndexView):
    @action('retour_admin', 'Retour à la page d\'administration', 'Êtes-vous sûr de vouloir revenir à la page d\'administration ?')
    def retour_admin(self, ids):
        return redirect(url_for('admin_page'))

admin = Admin(app, name='Admin', template_mode='bootstrap3', index_view=MyAdminView())

admin.add_view(ModelView(User, db.session, category='Gestion des tables Utilisateurs'))


# GESTION DE L'AUTHETIFICATION 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Définition du formulaire de connexion
class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Mot de passe', validators=[InputRequired(), Length(min=8, max=80,)])
    submit = SubmitField('Se connecter')

# Définition du formulaire d'inscription
class RegistrationForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Mot de passe', validators=[InputRequired(), Length(min=8, max=80)])
    confirm = PasswordField('Confirmer le mot de passe',validators=[InputRequired(), Length(min=8, max=80),EqualTo('password', message='Les mots de passe doivent correspondre')])
    submit = SubmitField('S\'inscrire')

# Route pour la page d'acceuil
@app.route('/')
def home():
    message = request.args.get('message') # Récupérer le message de la requête s'il y en a 
    if message:
        return render_template('h2.html', message=message)
    return render_template('h2.html')



# Route pour la page de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()

    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data

        user = User.query.filter_by(username=username).first()

        if user and sha256_crypt.verify(password, user.password):
            login_user(user)
            # Utilisez des identifiants et des mots de passe plus sécurisés pour l'administrateur
            if username == "admin" and sha256_crypt.verify("Aucune_idee!", user.password):
                return redirect(url_for('admin_page'))  # Rediriger vers la page admin
            else:
                return redirect(url_for('index'))
        else:
            error_message = 'Identifiant ou mot de passe incorrect'
            return render_template('l2.html', form=login_form, error_message=error_message)
    return render_template('l2.html', form=login_form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Utilisation de Passlib pour générer le hachage SHA-256 du mot de passe
        hashed_password = sha256_crypt.hash(form.password.data)
        
        # Utilisation du modèle User de la deuxième base de données
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('home', message='Nouvel utilisateur créé ! Connectez-vous maintenant'))
    
    return render_template('r2.html', form=form)

# Route pour la déconnexion de l'utilisateur
@app.route('/logout')
@login_required #  protégée par le décorateur @login_required, ce qui signifie que seuls les utilisateurs connectés pourront accéder à cette page. 
def logout():
    logout_user()
    return redirect(url_for('home'))

# Décorateur pour vérifier si l'utilisateur est un administrateur
def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != 'admin':
            return redirect(url_for('index'))  # Rediriger vers la page d'accueil si l'utilisateur n'est pas un administrateur
        return func(*args, **kwargs)
    return decorated_function

# Route où l'on est redirigé apres la connexion 
@app.route('/index')
@login_required
def index():
    return render_template('img.html', username = current_user.username)


# Route pour supprimer un client de la base de donnee 
@app.route('/delete_client/<int:user_id>', methods=['POST'])
@admin_required  # Utilisation du décorateur pour restreindre l'accès à l'administrateur
def delete_client(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('clients'))

'''
# Route pour la page clients securise avec un systeme d'authetification admin 
@app.route('/clients')
@admin_required #  protégée par le décorateur @admin_required, ce qui signifie que seuls les administrateurs  pourront accéder à cette page. 
def clients():
    username = request.authorization.username
    password = request.authorization.password

    if not check_credentials(username, password):
        return render_template('unauthorized.html'), 401

    all_users = User.query.all()
    return render_template('dataClient.html', users=all_users)
'''
@app.route('/clients')
#@jwt_required()   Ce décorateur exige un jeton JWT valide pour accéder à la route
@admin_required #  protégée par le décorateur @admin_required, ce qui signifie que seuls les administrateurs  pourront accéder à cette page. 
def clients():
    
    all_users = User.query.all()
    return render_template('dataClient.html', users=all_users)



# Nouvelle route pour la page d'administration
@app.route('/admin_page')
@login_required
def admin_page():
    return render_template('admin_page.html')


# interface de la base de donnees 

def is_admin(username):
    return username == "admin"

'''
@app.route('/admin')
@admin_required
def admin_panel():

    username = request.authorization.username

    if not is_admin(username):
        return render_template('unauthorized.html'), 401

    #return render_template('admin_panel.html')
'''

# Utiliser le port fourni par Heroku, ou 5000 en local
port = int(os.environ.get("PORT", 8009))
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)

'''
if __name__ == '__main__':
    app.run(debug=True, port=8009)

'''