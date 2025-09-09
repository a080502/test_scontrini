# app.py - File principale dell'applicazione
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
import os
from config import Config
from models.database import init_db
from routes.auth import auth_bp
from routes.main import main_bp
from routes.api import api_bp
from models.user import User

def create_app():
    """Factory pattern per creare l'app Flask"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Inizializza estensioni
    csrf = CSRFProtect(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Accesso richiesto per visualizzare questa pagina.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id: str) -> User:
        return User.get_by_id(int(user_id))
    
    # Registra blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Route principale che reindirizza alla dashboard
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('auth.login'))
    
    # Handler per errori
    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500
    
    return app

# config.py - Configurazione centralizzata
import os
from datetime import timedelta

class Config:
    """Configurazione base dell'applicazione"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    DATABASE_URL = os.environ.get('DATABASE_URL')
    WTF_CSRF_TIME_LIMIT = None  # CSRF token non scade
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Validazione configurazione
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL deve essere configurata nelle variabili d'ambiente")

# models/database.py - Gestione connessioni database
import psycopg2
import psycopg2.extras
from psycopg2 import pool
import urllib.parse
from typing import Optional
from contextlib import contextmanager
import atexit
from config import Config

class DatabaseManager:
    """Gestore centralizzato delle connessioni al database"""
    
    _pool: Optional[psycopg2.pool.SimpleConnectionPool] = None
    
    @classmethod
    def initialize_pool(cls) -> None:
        """Inizializza il pool di connessioni"""
        if cls._pool is None:
            url = urllib.parse.urlparse(Config.DATABASE_URL)
            cls._pool = psycopg2.pool.SimpleConnectionPool(
                1, 20,  # min e max connessioni
                host=url.hostname,
                port=url.port,
                database=url.path[1:],
                user=url.username,
                password=url.password,
                cursor_factory=psycopg2.extras.RealDictCursor,
                sslmode='require'
            )
            # Registra cleanup al termine dell'app
            atexit.register(cls.close_pool)
    
    @classmethod
    def close_pool(cls) -> None:
        """Chiude il pool di connessioni"""
        if cls._pool:
            cls._pool.closeall()
            cls._pool = None
    
    @classmethod
    @contextmanager
    def get_connection(self):
        """Context manager per ottenere una connessione dal pool"""
        if not self._pool:
            self.initialize_pool()
        
        conn = None
        try:
            conn = self._pool.getconn()
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                self._pool.putconn(conn)

def init_db() -> None:
    """Inizializza il database creando le tabelle necessarie"""
    with DatabaseManager.get_connection() as conn:
        cursor = conn.cursor()
        
        print("Inizializzazione database...")
        
        # Tabella scontrini
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scontrini (
                id SERIAL PRIMARY KEY,
                data_scontrino DATE NOT NULL,
                nome_scontrino TEXT NOT NULL,
                importo_versare DECIMAL(10,2) NOT NULL,
                importo_incassare DECIMAL(10,2) NOT NULL,
                incassato BOOLEAN DEFAULT FALSE,
                data_incasso TIMESTAMP NULL,
                versato BOOLEAN DEFAULT FALSE,
                data_versamento TIMESTAMP NULL,
                data_inserimento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                archiviato BOOLEAN DEFAULT FALSE,
                user_id INTEGER REFERENCES users(id)
            )
        ''')
        
        # Tabella users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                filiale TEXT,
                utente TEXT,
                nome_utente TEXT NOT NULL,
                mail TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                campo_libero1 TEXT,
                campo_libero2 TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            )
        ''')
        
        # Aggiunge colonna user_id se non esiste
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'scontrini' AND column_name = 'user_id'
        """)
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE scontrini ADD COLUMN user_id INTEGER REFERENCES users(id)')
        
        conn.commit()
        print("Database inizializzato con successo!")

# models/user.py - Modello User con Flask-Login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Optional, Dict, Any
from datetime import datetime
from models.database import DatabaseManager

class User(UserMixin):
    """Modello User per gestione autenticazione"""
    
    def __init__(self, id: int, mail: str, nome_utente: str, password_hash: str,
                 filiale: str = None, utente: str = None, campo_libero1: str = None,
                 campo_libero2: str = None, is_active: bool = True, is_admin: bool = False,
                 created_at: datetime = None, last_login: datetime = None):
        self.id = id
        self.mail = mail
        self.nome_utente = nome_utente
        self.password_hash = password_hash
        self.filiale = filiale
        self.utente = utente
        self.campo_libero1 = campo_libero1
        self.campo_libero2 = campo_libero2
        self._is_active = is_active
        self.is_admin = is_admin
        self.created_at = created_at
        self.last_login = last_login
    
    @property
    def is_active(self) -> bool:
        return self._is_active
    
    def check_password(self, password: str) -> bool:
        """Verifica la password dell'utente"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self) -> None:
        """Aggiorna timestamp ultimo login"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s',
                (self.id,)
            )
            conn.commit()
    
    @classmethod
    def get_by_id(cls, user_id: int) -> Optional['User']:
        """Ottiene utente per ID"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            row = cursor.fetchone()
            return cls._from_db_row(row) if row else None
    
    @classmethod
    def get_by_email(cls, email: str) -> Optional['User']:
        """Ottiene utente per email"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE mail = %s', (email,))
            row = cursor.fetchone()
            return cls._from_db_row(row) if row else None
    
    @classmethod
    def create_user(cls, mail: str, nome_utente: str, password: str,
                   filiale: str = None, utente: str = None,
                   campo_libero1: str = None, campo_libero2: str = None) -> 'User':
        """Crea un nuovo utente"""
        password_hash = generate_password_hash(password)
        
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (filiale, utente, nome_utente, mail, password_hash, 
                                 campo_libero1, campo_libero2)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
            ''', (filiale, utente, nome_utente, mail, password_hash, campo_libero1, campo_libero2))
            
            user_id = cursor.fetchone()['id']
            conn.commit()
            
            return cls.get_by_id(user_id)
    
    @classmethod
    def _from_db_row(cls, row: Dict[str, Any]) -> 'User':
        """Crea istanza User da riga database"""
        return cls(**row)

# models/scontrino.py - Modello e servizi per scontrini
from typing import List, Dict, Optional, Tuple
from datetime import datetime, date
from decimal import Decimal
from collections import defaultdict
from models.database import DatabaseManager

class ScontrinoService:
    """Servizio per gestione scontrini e calcoli finanziari"""
    
    @staticmethod
    def validate_date(date_string: str) -> str:
        """Valida e corregge il formato della data"""
        try:
            parsed_date = datetime.strptime(date_string, '%Y-%m-%d')
            if not (1900 <= parsed_date.year <= 2100):
                raise ValueError(f"Anno non valido: {parsed_date.year}")
            return parsed_date.strftime('%Y-%m-%d')
        except (ValueError, TypeError):
            return datetime.now().strftime('%Y-%m-%d')
    
    @staticmethod
    def get_all_active(user_id: Optional[int] = None) -> List[Dict]:
        """Ottiene tutti gli scontrini attivi"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            query = 'SELECT * FROM scontrini WHERE archiviato = FALSE'
            params = []
            
            if user_id:
                query += ' AND user_id = %s'
                params.append(user_id)
                
            cursor.execute(query, params)
            return cursor.fetchall()
    
    @staticmethod
    def get_recent(limit: int = 5, user_id: Optional[int] = None) -> List[Dict]:
        """Ottiene scontrini recenti"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            query = '''SELECT * FROM scontrini WHERE archiviato = FALSE 
                      ORDER BY data_inserimento DESC LIMIT %s'''
            params = [limit]
            
            if user_id:
                query = query.replace('WHERE', 'WHERE user_id = %s AND')
                params.insert(0, user_id)
                
            cursor.execute(query, params)
            return cursor.fetchall()
    
    @staticmethod
    def get_filtered(filtro: str, user_id: Optional[int] = None) -> Tuple[List[Dict], str]:
        """Ottiene scontrini filtrati"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            base_query = 'SELECT * FROM scontrini WHERE archiviato = FALSE'
            order_clause = ' ORDER BY nome_scontrino, data_scontrino DESC'
            params = []
            
            if user_id:
                base_query += ' AND user_id = %s'
                params.append(user_id)
            
            if filtro == 'incassati':
                query = base_query + ' AND incassato = TRUE' + order_clause
                titolo = "Scontrini Incassati"
            elif filtro == 'da_incassare':
                query = base_query + ' AND incassato = FALSE' + order_clause
                titolo = "Scontrini da Incassare"
            else:
                query = base_query + order_clause
                titolo = "Tutti gli Scontrini"
            
            cursor.execute(query, params)
            return cursor.fetchall(), titolo
    
    @staticmethod
    def get_archived(user_id: Optional[int] = None) -> List[Dict]:
        """Ottiene scontrini archiviati"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            query = 'SELECT * FROM scontrini WHERE archiviato = TRUE ORDER BY data_inserimento DESC'
            params = []
            
            if user_id:
                query = query.replace('WHERE', 'WHERE user_id = %s AND')
                params.append(user_id)
                
            cursor.execute(query, params)
            return cursor.fetchall()
    
    @staticmethod
    def calculate_financial_stats(scontrini: List[Dict]) -> Dict[str, Decimal]:
        """Calcola statistiche finanziarie"""
        stats = {
            'totale_da_versare_complessivo': Decimal('0'),
            'totale_incassare': Decimal('0'),
            'totale_incassato': Decimal('0'),
            'totale_versato': Decimal('0'),
            'num_scontrini': len(scontrini),
            'num_incassati': 0,
        }
        
        for s in scontrini:
            importo_versare = Decimal(str(s['importo_versare'] or 0))
            importo_incassare = Decimal(str(s['importo_incassare'] or 0))
            
            stats['totale_da_versare_complessivo'] += importo_versare
            stats['totale_incassare'] += importo_incassare
            
            if s['incassato']:
                stats['totale_incassato'] += importo_incassare
                stats['num_incassati'] += 1
            
            if s['versato']:
                stats['totale_versato'] += importo_versare
        
        # Calcoli derivati
        stats['totale_da_incassare'] = stats['totale_incassare'] - stats['totale_incassato']
        stats['ancora_da_versare'] = stats['totale_da_versare_complessivo'] - stats['totale_versato']
        stats['cassa'] = stats['totale_incassato'] - stats['totale_versato']
        stats['num_da_incassare'] = stats['num_scontrini'] - stats['num_incassati']
        
        return stats
    
    @staticmethod
    def group_by_name(scontrini: List[Dict]) -> Dict:
        """Raggruppa scontrini per nome con subtotali"""
        grouped = defaultdict(lambda: {
            'scontrini': [],
            'subtotali': defaultdict(Decimal)
        })
        
        for s in scontrini:
            nome = s['nome_scontrino']
            gruppo = grouped[nome]
            gruppo['scontrini'].append(s)
            
            importo_versare = Decimal(str(s['importo_versare'] or 0))
            importo_incassare = Decimal(str(s['importo_incassare'] or 0))
            
            gruppo['subtotali']['importo_versare'] += importo_versare
            gruppo['subtotali']['importo_incassare'] += importo_incassare
            
            if s['incassato']:
                gruppo['subtotali']['incassato'] += importo_incassare
            if s['versato']:
                gruppo['subtotali']['versato'] += importo_versare
        
        # Calcola cassa per ogni gruppo
        for gruppo in grouped.values():
            gruppo['subtotali']['cassa'] = (
                gruppo['subtotali']['incassato'] - gruppo['subtotali']['versato']
            )
        
        return dict(grouped)
    
    @staticmethod
    def create_scontrino(data_scontrino: str, nome_scontrino: str,
                        importo_versare: float, importo_incassare: float,
                        user_id: int) -> int:
        """Crea nuovo scontrino"""
        validated_date = ScontrinoService.validate_date(data_scontrino)
        
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scontrini (data_scontrino, nome_scontrino, importo_versare, 
                                     importo_incassare, user_id)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            ''', (validated_date, nome_scontrino, importo_versare, importo_incassare, user_id))
            
            scontrino_id = cursor.fetchone()['id']
            conn.commit()
            return scontrino_id
    
    @staticmethod
    def update_scontrino(scontrino_id: int, data_scontrino: str, nome_scontrino: str,
                        importo_versare: float, importo_incassare: float) -> bool:
        """Aggiorna scontrino esistente"""
        validated_date = ScontrinoService.validate_date(data_scontrino)
        
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scontrini
                SET data_scontrino=%s, nome_scontrino=%s, importo_versare=%s, importo_incassare=%s
                WHERE id=%s
            ''', (validated_date, nome_scontrino, importo_versare, importo_incassare, scontrino_id))
            conn.commit()
            return cursor.rowcount > 0
    
    @staticmethod
    def get_by_id(scontrino_id: int) -> Optional[Dict]:
        """Ottiene scontrino per ID"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scontrini WHERE id = %s', (scontrino_id,))
            return cursor.fetchone()
    
    @staticmethod
    def toggle_incasso(scontrino_id: int, incassato: bool) -> bool:
        """Cambia stato incasso"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            if incassato:
                cursor.execute(
                    'UPDATE scontrini SET incassato = TRUE, data_incasso = CURRENT_TIMESTAMP WHERE id = %s',
                    (scontrino_id,)
                )
            else:
                cursor.execute(
                    'UPDATE scontrini SET incassato = FALSE, data_incasso = NULL, versato = FALSE, data_versamento = NULL WHERE id = %s',
                    (scontrino_id,)
                )
            conn.commit()
            return cursor.rowcount > 0
    
    @staticmethod
    def toggle_versamento(scontrino_id: int, versato: bool) -> bool:
        """Cambia stato versamento"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            if versato:
                cursor.execute(
                    'UPDATE scontrini SET versato = TRUE, data_versamento = CURRENT_TIMESTAMP WHERE id = %s',
                    (scontrino_id,)
                )
            else:
                cursor.execute(
                    'UPDATE scontrini SET versato = FALSE, data_versamento = NULL WHERE id = %s',
                    (scontrino_id,)
                )
            conn.commit()
            return cursor.rowcount > 0
    
    @staticmethod
    def toggle_archiviazione(scontrino_id: int, archiviato: bool) -> bool:
        """Cambia stato archiviazione"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE scontrini SET archiviato = %s WHERE id = %s',
                (archiviato, scontrino_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    
    @staticmethod
    def delete_scontrino(scontrino_id: int) -> bool:
        """Elimina scontrino definitivamente"""
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scontrini WHERE id = %s', (scontrino_id,))
            conn.commit()
            return cursor.rowcount > 0

# forms/auth.py - Form per autenticazione
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models.user import User

class LoginForm(FlaskForm):
    """Form per il login"""
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Ricordami')
    submit = SubmitField('Accedi')

class RegistrationForm(FlaskForm):
    """Form per la registrazione"""
    nome_utente = StringField('Nome Utente', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Conferma Password', validators=[
        DataRequired(), EqualTo('password', message='Le password non corrispondono')
    ])
    filiale = StringField('Filiale', validators=[Length(max=100)])
    utente = StringField('Utente', validators=[Length(max=100)])
    campo_libero1 = StringField('Campo Libero 1', validators=[Length(max=200)])
    campo_libero2 = StringField('Campo Libero 2', validators=[Length(max=200)])
    submit = SubmitField('Registrati')
    
    def validate_email(self, email):
        """Valida che l'email non sia già in uso"""
        user = User.get_by_email(email.data)
        if user:
            raise ValidationError('Questa email è già registrata.')

# forms/scontrino.py - Form per scontrini
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, DateField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length
from datetime import date

class ScontrinoForm(FlaskForm):
    """Form per creazione/modifica scontrini"""
    data_scontrino = DateField(
        'Data Scontrino',
        validators=[DataRequired()],
        default=date.today,
        render_kw={"class": "form-control"}
    )
    nome_scontrino = StringField(
        'Nome Scontrino',
        validators=[DataRequired(), Length(min=1, max=200)],
        render_kw={"class": "form-control", "placeholder": "Inserisci il nome dello scontrino"}
    )
    importo_versare = DecimalField(
        'Importo da Versare',
        validators=[DataRequired(), NumberRange(min=0, message="L'importo deve essere positivo")],
        places=2,
        render_kw={"class": "form-control", "step": "0.01", "placeholder": "0.00"}
    )
    importo_incassare = DecimalField(
        'Importo da Incassare',
        validators=[DataRequired(), NumberRange(min=0, message="L'importo deve essere positivo")],
        places=2,
        render_kw={"class": "form-control", "step": "0.01", "placeholder": "0.00"}
    )
    submit = SubmitField('Salva', render_kw={"class": "btn btn-primary"})

# routes/auth.py - Route per autenticazione
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from forms.auth import LoginForm, RegistrationForm
from models.user import User

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Route per il login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.update_last_login()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('main.dashboard')
            
            flash(f'Benvenuto {user.nome_utente}!', 'success')
            return redirect(next_page)
        else:
            flash('Email o password non validi.', 'danger')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
def logout():
    """Route per il logout"""
    logout_user()
    flash('Logout effettuato con successo.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Route per la registrazione"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User.create_user(
                mail=form.email.data,
                nome_utente=form.nome_utente.data,
                password=form.password.data,
                filiale=form.filiale.data,
                utente=form.utente.data,
                campo_libero1=form.campo_libero1.data,
                campo_libero2=form.campo_libero2.data
            )
            flash('Registrazione completata con successo! Puoi ora effettuare il login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash(f'Errore durante la registrazione: {str(e)}', 'danger')
    
    return render_template('auth/register.html', form=form)

# routes/main.py - Route principali
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from forms.scontrino import ScontrinoForm
from models.scontrino import ScontrinoService
from typing import Dict, Any

main_bp = Blueprint('main', __name__)

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principale"""
    try:
        # Ottieni dati per il dashboard
        scontrini = ScontrinoService.get_all_active(current_user.id)
        ultimi_scontrini = ScontrinoService.get_recent(5, current_user.id)
        
        # Calcola statistiche
        stats = ScontrinoService.calculate_financial_stats(scontrini)
        
        # Conta scontrini archiviati
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM scontrini WHERE archiviato = TRUE AND user_id = %s', (current_user.id,))
            stats['num_archiviati'] = cursor.fetchone()['count']
        
        return render_template('main/dashboard.html', 
                             ultimi_scontrini=ultimi_scontrini,
                             **stats)
    except Exception as e:
        flash(f'Errore nel caricamento del dashboard: {str(e)}', 'danger')
        return render_template('main/dashboard.html')

@main_bp.route('/lista')
@login_required
def lista_scontrini():
    """Lista scontrini con filtri"""
    try:
        filtro = request.args.get('filtro', 'tutti')
        scontrini, titolo = ScontrinoService.get_filtered(filtro, current_user.id)
        
        # Raggruppa scontrini
        scontrini_raggruppati = ScontrinoService.group_by_name(scontrini)
        
        # Calcola totali
        stats = ScontrinoService.calculate_financial_stats(scontrini)
        
        return render_template('main/lista.html',
                             scontrini_raggruppati=scontrini_raggruppati,
                             filtro=filtro,
                             titolo=titolo,
                             num_elementi=len(scontrini),
                             **stats)
    except Exception as e:
        flash(f'Errore nel caricamento della lista: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))

@main_bp.route('/archivio')
@login_required
def archivio():
    """Visualizza scontrini archiviati"""
    try:
        scontrini_archiviati = ScontrinoService.get_archived(current_user.id)
        scontrini_raggruppati = ScontrinoService.group_by_name(scontrini_archiviati)
        
        # Calcola totali per l'archivio
        totale_incassato = sum(float(s['importo_incassare'] or 0) for s in scontrini_archiviati)
        totale_versato = sum(float(s['importo_versare'] or 0) for s in scontrini_archiviati)
        
        return render_template('main/archivio.html',
                             scontrini_raggruppati=scontrini_raggruppati,
                             num_elementi=len(scontrini_archiviati),
                             totale_incassato_archivio=totale_incassato,
                             totale_versato_archivio=totale_versato)
    except Exception as e:
        flash(f'Errore nel caricamento dell\'archivio: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))

@main_bp.route('/aggiungi', methods=['GET', 'POST'])
@login_required
def aggiungi_scontrino():
    """Aggiungi nuovo scontrino"""
    form = ScontrinoForm()
    
    if form.validate_on_submit():
        try:
            ScontrinoService.create_scontrino(
                data_scontrino=form.data_scontrino.data.strftime('%Y-%m-%d'),
                nome_scontrino=form.nome_scontrino.data,
                importo_versare=float(form.importo_versare.data),
                importo_incassare=float(form.importo_incassare.data),
                user_id=current_user.id
            )
            flash('Scontrino aggiunto con successo!', 'success')
            return redirect(url_for('main.lista_scontrini'))
        except Exception as e:
            flash(f'Errore nell\'aggiunta dello scontrino: {str(e)}', 'danger')
    
    return render_template('main/aggiungi.html', form=form)

@main_bp.route('/modifica/<int:id>', methods=['GET', 'POST'])
@login_required
def modifica_scontrino(id: int):
    """Modifica scontrino esistente"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Scontrino non trovato o non autorizzato.', 'danger')
            return redirect(url_for('main.lista_scontrini'))
        
        form = ScontrinoForm()
        
        if form.validate_on_submit():
            success = ScontrinoService.update_scontrino(
                scontrino_id=id,
                data_scontrino=form.data_scontrino.data.strftime('%Y-%m-%d'),
                nome_scontrino=form.nome_scontrino.data,
                importo_versare=float(form.importo_versare.data),
                importo_incassare=float(form.importo_incassare.data)
            )
            
            if success:
                flash('Scontrino modificato con successo!', 'success')
                return redirect(url_for('main.lista_scontrini'))
            else:
                flash('Errore nella modifica dello scontrino.', 'danger')
        
        # Pre-popola il form con i dati esistenti
        if request.method == 'GET':
            from datetime import datetime
            form.data_scontrino.data = datetime.strptime(str(scontrino['data_scontrino']), '%Y-%m-%d').date()
            form.nome_scontrino.data = scontrino['nome_scontrino']
            form.importo_versare.data = scontrino['importo_versare']
            form.importo_incassare.data = scontrino['importo_incassare']
        
        return render_template('main/modifica.html', form=form, scontrino=scontrino)
    except Exception as e:
        flash(f'Errore nella modifica: {str(e)}', 'danger')
        return redirect(url_for('main.lista_scontrini'))

@main_bp.route('/incassa/<int:id>')
@login_required
def incassa_scontrino(id: int):
    """Segna scontrino come incassato"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_incasso(id, True)
            flash('Scontrino incassato!', 'success')
    except Exception as e:
        flash(f'Errore nell\'incasso: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('main.lista_scontrini'))

@main_bp.route('/annulla_incasso/<int:id>')
@login_required
def annulla_incasso(id: int):
    """Annulla incasso scontrino"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_incasso(id, False)
            flash('Incasso annullato!', 'success')
    except Exception as e:
        flash(f'Errore nell\'annullamento: {str(e)}', 'danger')
    
    return redirect(url_for('main.lista_scontrini'))

@main_bp.route('/versa/<int:id>')
@login_required
def versa_scontrino(id: int):
    """Segna scontrino come versato"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_versamento(id, True)
            flash('Scontrino versato!', 'success')
    except Exception as e:
        flash(f'Errore nel versamento: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('main.lista_scontrini'))

@main_bp.route('/annulla_versamento/<int:id>')
@login_required
def annulla_versamento(id: int):
    """Annulla versamento scontrino"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_versamento(id, False)
            flash('Versamento annullato!', 'success')
    except Exception as e:
        flash(f'Errore nell\'annullamento: {str(e)}', 'danger')
    
    return redirect(url_for('main.lista_scontrini'))

@main_bp.route('/archivia/<int:id>')
@login_required
def archivia_scontrino(id: int):
    """Archivia scontrino"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_archiviazione(id, True)
            flash('Scontrino archiviato!', 'success')
    except Exception as e:
        flash(f'Errore nell\'archiviazione: {str(e)}', 'danger')
    
    return redirect(url_for('main.lista_scontrini'))

@main_bp.route('/annulla_archiviazione/<int:id>')
@login_required
def annulla_archiviazione(id: int):
    """Annulla archiviazione scontrino"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            flash('Non autorizzato.', 'danger')
        else:
            ScontrinoService.toggle_archiviazione(id, False)
            flash('Archiviazione annullata!', 'success')
    except Exception as e:
        flash(f'Errore nell\'annullamento: {str(e)}', 'danger')
    
    return redirect(url_for('main.archivio'))

@main_bp.route('/elimina/<int:id>')
@login_required
def elimina_scontrino(id: int):
    """Elimina definitivamente scontrino (solo admin)"""
    try:
        if not current_user.is_admin:
            flash('Solo gli amministratori possono eliminare definitivamente i scontrini.', 'danger')
            return redirect(url_for('main.lista_scontrini'))
        
        success = ScontrinoService.delete_scontrino(id)
        if success:
            flash('Scontrino eliminato definitivamente!', 'warning')
        else:
            flash('Errore nell\'eliminazione.', 'danger')
    except Exception as e:
        flash(f'Errore nell\'eliminazione: {str(e)}', 'danger')
    
    return redirect(url_for('main.lista_scontrini'))

@main_bp.route('/lista-utenti')
@login_required
def lista_utenti():
    """Lista utenti (solo per admin)"""
    if not current_user.is_admin:
        flash('Accesso negato.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    try:
        from models.database import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, filiale, utente, nome_utente, mail, campo_libero1, 
                       campo_libero2, created_at, last_login, is_active, is_admin
                FROM users ORDER BY created_at DESC
            ''')
            utenti = cursor.fetchall()
        
        return render_template('main/lista_utenti.html', utenti=utenti)
    except Exception as e:
        flash(f'Errore nel caricamento degli utenti: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))

# routes/api.py - API REST per operazioni AJAX
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models.scontrino import ScontrinoService

api_bp = Blueprint('api', __name__)

@api_bp.route('/stats')
@login_required
def get_stats():
    """API per ottenere statistiche in tempo reale"""
    try:
        scontrini = ScontrinoService.get_all_active(current_user.id)
        stats = ScontrinoService.calculate_financial_stats(scontrini)
        
        # Converte Decimal in float per JSON serialization
        return jsonify({
            key: float(value) if hasattr(value, '__float__') else value
            for key, value in stats.items()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/scontrino/<int:id>/toggle/<action>', methods=['POST'])
@login_required
def toggle_scontrino_status(id: int, action: str):
    """API per cambiare stato scontrini via AJAX"""
    try:
        scontrino = ScontrinoService.get_by_id(id)
        if not scontrino or (scontrino['user_id'] != current_user.id and not current_user.is_admin):
            return jsonify({'error': 'Non autorizzato'}), 403
        
        if action == 'incasso':
            new_status = not scontrino['incassato']
            success = ScontrinoService.toggle_incasso(id, new_status)
            message = 'Incassato' if new_status else 'Incasso annullato'
        elif action == 'versamento':
            new_status = not scontrino['versato']
            success = ScontrinoService.toggle_versamento(id, new_status)
            message = 'Versato' if new_status else 'Versamento annullato'
        elif action == 'archiviazione':
            new_status = not scontrino['archiviato']
            success = ScontrinoService.toggle_archiviazione(id, new_status)
            message = 'Archiviato' if new_status else 'Archiviazione annullata'
        else:
            return jsonify({'error': 'Azione non valida'}), 400
        
        if success:
            return jsonify({'success': True, 'message': message, 'new_status': new_status})
        else:
            return jsonify({'error': 'Operazione fallita'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# run.py - Entry point per avviare l'app
from app import create_app
from models.database import init_db, DatabaseManager
import os

if __name__ == '__main__':
    try:
        # Inizializza database e pool connessioni
        DatabaseManager.initialize_pool()
        init_db()
        
        # Crea app
        app = create_app()
        
        # Avvia server
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_ENV') == 'development'
        
        app.run(host='0.0.0.0', port=port, debug=debug)
        
    except Exception as e:
        print(f"Errore fatale nell'avvio dell'applicazione: {e}")

# requirements.txt - Dipendenze Python
"""
Flask==2.3.3
Flask-Login==0.6.3
Flask-WTF==1.1.1
WTForms==3.0.1
psycopg2-binary==2.9.7
Werkzeug==2.3.7
python-dotenv==1.0.0
"""

# .env.example - Template per variabili d'ambiente
"""
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@host:port/database
FLASK_ENV=development
PORT=5000
"""

# templates/base.html - Template base con Bootstrap e sicurezza
"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{% block title %}Gestione Scontrini{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('main.dashboard') }}">
                <i class="fas fa-receipt me-2"></i>Gestione Scontrini
            </a>
            
            {% if current_user.is_authenticated %}
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.dashboard') }}">
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.lista_scontrini') }}">
                            <i class="fas fa-list me-1"></i>Scontrini
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.aggiungi_scontrino') }}">
                            <i class="fas fa-plus me-1"></i>Aggiungi
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.archivio') }}">
                            <i class="fas fa-archive me-1"></i>Archivio
                        </a>
                    </li>
                    {% if current_user.is_admin %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.lista_utenti') }}">
                            <i class="fas fa-users me-1"></i>Utenti
                        </a>
                    </li>
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i>{{ current_user.nome_utente }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ url_for('auth.logout') }}">
                                <i class="fas fa-sign-out-alt me-2"></i>Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
            {% endif %}
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- Main Content -->
    <main class="container my-4">
        {% block content %}{% endblock %}
    </main>

    <!-- Footer -->
    <footer class="bg-light py-4 mt-5">
        <div class="container text-center">
            <p class="mb-0">&copy; 2024 Gestione Scontrini. Versione 2.0 - Sicura e Ottimizzata</p>
        </div>
    </footer>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // CSRF token per AJAX requests
        window.csrf_token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        
        // Configurazione AJAX con CSRF
        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader("X-CSRFToken", window.csrf_token);
                }
            }
        });
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
"""

# Documentazione README.md
"""
# Gestione Scontrini v2.0

Sistema di gestione scontrini Flask completamente ristrutturato con sicurezza avanzata.

## 🚀 Nuove Funzionalità

### Architettura Migliorata
- **Separazione MVC**: Modelli, Route e Template separati
- **Connection Pooling**: Gestione ottimizzata delle connessioni DB
- **Services Layer**: Logica business centralizzata

### Sicurezza Avanzata
- **Flask-Login**: Gestione sessioni sicura
- **Flask-WTF**: Validazione form e protezione CSRF
- **Autorizzazione**: Controlli di accesso per utente/admin
- **Password Hashing**: Werkzeug security per password

### User Experience
- **Bootstrap 5**: Interfaccia moderna e responsive
- **AJAX API**: Operazioni in tempo reale
- **Flash Messages**: Feedback immediato
- **Form Validation**: Validazione client e server-side

## 📁 Struttura del Progetto

```
app/
├── app.py              # Factory app principale
├── config.py           # Configurazione centralizzata
├── run.py              # Entry point
├── models/
│   ├── __init__.py
│   ├── database.py     # Gestione DB e connection pool
│   ├── user.py         # Modello User con Flask-Login
│   └── scontrino.py    # Servizi per scontrini
├── forms/
│   ├── __init__.py
│   ├── auth.py         # Form autenticazione
│   └── scontrino.py    # Form scontrini
├── routes/
│   ├── __init__.py
│   ├── auth.py         # Route autenticazione
│   ├── main.py         # Route principali
│   └── api.py          # API REST
└── templates/
    ├── base.html       # Template base
    ├── auth/           # Template autenticazione
    ├── main/           # Template principali
    └── errors/         # Template errori
```

## ⚙️ Installazione

1. **Installa dipendenze**:
```bash
pip install -r requirements.txt
```

2. **Configura variabili d'ambiente**:
```bash
cp .env.example .env
# Modifica .env con le tue configurazioni
```

3. **Avvia l'applicazione**:
```bash
python run.py
```

## 🔐 Sicurezza Implementata

- ✅ **CSRF Protection** su tutti i form
- ✅ **SQL Injection Prevention** con parametri preparati
- ✅ **Password Hashing** con Werkzeug
- ✅ **Session Management** sicuro con Flask-Login
- ✅ **Input Validation** lato client e server
- ✅ **Authorization Checks** per ogni operazione

## 📊 API Endpoints

### Autenticazione
- `POST /auth/login` - Login utente
- `GET /auth/logout` - Logout utente
- `POST /auth/register` - Registrazione nuovo utente

### Scontrini
- `GET /dashboard` - Dashboard principale
- `GET /lista` - Lista scontrini con filtri
- `POST /aggiungi` - Nuovo scontrino
- `POST /modifica/<id>` - Modifica scontrino
- `GET /incassa/<id>` - Incassa scontrino
- `GET /versa/<id>` - Versa scontrino
- `GET /archivia/<id>` - Archivia scontrino

### API REST
- `GET /api/stats` - Statistiche in tempo reale
- `POST /api/scontrino/<id>/toggle/<action>` - Toggle stati via AJAX

## 🔧 Configurazione Avanzata

### Database Connection Pool
```python
# Configurazione pool nelle variabili d'ambiente
DB_POOL_MIN=1
DB_POOL_MAX=20
```

### Sicurezza Aggiuntiva
```python
# config.py
class ProductionConfig(Config):
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF token scade in 1 ora
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)  # Sessione 8 ore
    SESSION_COOKIE_SECURE = True  # Solo HTTPS
    SESSION_COOKIE_HTTPONLY = True  # No accesso JS
```

## 🚀 Deployment

### Render.com
```yaml
# render.yaml
services:
  - type: web
    name: gestione-scontrini
    env: python
    buildCommand: "pip install -r requirements.txt"
    startCommand: "python run.py"
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: DATABASE_URL
        fromDatabase:
          name: gestione-scontrini-db
```

### Heroku
```bash
# Procfile
web: python run.py
```

## 📈 Performance

- **Connection Pooling**: Riutilizzo connessioni DB
- **Lazy Loading**: Caricamento dati on-demand
- **AJAX Updates**: Aggiornamenti senza refresh
- **Caching**: Template e query cache

## 🧪 Testing

```bash
# Test unitari
python -m pytest tests/

# Test copertura
coverage run -m pytest tests/
coverage report -m
```

## 📋 TODO Futuro

- [ ] **Rate Limiting** per login attempts
- [ ] **Email Verification** per nuovi utenti
- [ ] **Two-Factor Authentication** (2FA)
- [ ] **Audit Log** per tutte le operazioni
- [ ] **Export Data** in Excel/PDF
- [ ] **Dashboard Analytics** avanzate
- [ ] **Mobile App** con API REST
- [ ] **Backup Automatici** programmati

## 🛠️ Troubleshooting

### Errori Comuni

1. **Database Connection Error**:
   - Verifica DATABASE_URL in .env
   - Controlla connessione PostgreSQL

2. **CSRF Token Missing**:
   - Verifica che tutti i form abbiano {{ csrf_token() }}
   - Controlla configurazione Flask-WTF

3. **Permission Denied**:
   - Verifica autorizzazioni user_id sui dati
   - Controlla is_admin per operazioni privilegiate

## 📞 Supporto

Per problemi o suggerimenti, apri un issue nel repository.

---

**Versione 2.0** - Completamente ristrutturata per sicurezza e scalabilità massime! 🎉
"""