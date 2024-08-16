from flask import Flask, render_template, request, redirect, url_for, flash,session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
import sklearn
import pickle
import warnings
from sklearn.exceptions import InconsistentVersionWarning
import random

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
import secrets
import os
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Replace with your MySQL username
app.config['MYSQL_PASSWORD'] = 'Johnwick_09'  # Replace with your MySQL password
app.config['MYSQL_DB'] = 'crop_recommendation'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# Flask-Mail configuration


mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# Static admin credentials
ADMIN_USERNAME = 'vani'
ADMIN_PASSWORD = 'alchemist'  # Replace with your desired admin password

# Hash the password
ADMIN_PASSWORD_HASH = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')

MODEL_PATH=r'crop_recommendation_model.pkl'
with open(MODEL_PATH, 'rb') as model_file:
    model = pickle.load(model_file)



optimal_conditions = {
    'rice': {'N': 90, 'P': 42, 'K': 42, 'temperature': 25, 'humidity': 80, 'ph': 6.5, 'rainfall': 150},
    'maize': {'N': 120, 'P': 60, 'K': 50, 'temperature': 24, 'humidity': 70, 'ph': 6.0, 'rainfall': 50},
    'chickpea': {'N': 30, 'P': 65, 'K': 80, 'temperature': 20, 'humidity': 17, 'ph': 7.0, 'rainfall': 80},
    'kidneybeans': {'N': 20, 'P': 67, 'K': 60, 'temperature': 25, 'humidity': 50, 'ph': 6.5, 'rainfall': 80},
    'pigeonpeas': {'N': 30, 'P': 50, 'K': 50, 'temperature': 23, 'humidity': 20, 'ph': 6.3, 'rainfall': 60},
    'mothbeans': {'N': 25, 'P': 45, 'K': 55, 'temperature': 25, 'humidity': 30, 'ph': 7.0, 'rainfall': 70},
    'mungbean': {'N': 20, 'P': 50, 'K': 60, 'temperature': 28, 'humidity': 40, 'ph': 7.0, 'rainfall': 60},
    'blackgram': {'N': 30, 'P': 60, 'K': 40, 'temperature': 27, 'humidity': 50, 'ph': 6.5, 'rainfall': 70},
    'lentil': {'N': 10, 'P': 60, 'K': 70, 'temperature': 24, 'humidity': 30, 'ph': 6.5, 'rainfall': 50},
    'pomegranate': {'N': 100, 'P': 50, 'K': 50, 'temperature': 27, 'humidity': 30, 'ph': 6.5, 'rainfall': 50},
    'banana': {'N': 110, 'P': 50, 'K': 55, 'temperature': 27, 'humidity': 80, 'ph': 6.5, 'rainfall': 100},
    'mango': {'N': 60, 'P': 50, 'K': 50, 'temperature': 27, 'humidity': 70, 'ph': 5.5, 'rainfall': 200},
    'grapes': {'N': 100, 'P': 60, 'K': 50, 'temperature': 23, 'humidity': 60, 'ph': 6.0, 'rainfall': 50},
    'watermelon': {'N': 100, 'P': 50, 'K': 40, 'temperature': 25, 'humidity': 60, 'ph': 6.5, 'rainfall': 100},
    'muskmelon': {'N': 90, 'P': 60, 'K': 50, 'temperature': 30, 'humidity': 50, 'ph': 6.5, 'rainfall': 50},
    'apple': {'N': 100, 'P': 100, 'K': 100, 'temperature': 24, 'humidity': 70, 'ph': 6.5, 'rainfall': 120},
    'orange': {'N': 100, 'P': 50, 'K': 50, 'temperature': 25, 'humidity': 60, 'ph': 6.5, 'rainfall': 150},
    'papaya': {'N': 100, 'P': 60, 'K': 50, 'temperature': 25, 'humidity': 80, 'ph': 6.0, 'rainfall': 150},
    'coconut': {'N': 120, 'P': 50, 'K': 60, 'temperature': 27, 'humidity': 80, 'ph': 6.0, 'rainfall': 100},
    'cotton': {'N': 100, 'P': 50, 'K': 60, 'temperature': 25, 'humidity': 60, 'ph': 6.0, 'rainfall': 100},
    'jute': {'N': 100, 'P': 50, 'K': 60, 'temperature': 25, 'humidity': 60, 'ph': 6.5, 'rainfall': 100},
    'coffee': {'N': 100, 'P': 50, 'K': 60, 'temperature': 24, 'humidity': 70, 'ph': 6.0, 'rainfall': 100}


}

# Function to calculate Euclidean distance between two points
def calculate_distance(input_conditions, crop_conditions):
    distance = 0
    for key in input_conditions:
        distance += (input_conditions[key] - crop_conditions[key]) ** 2
    return math.sqrt(distance)

# Function to recommend top 3 crops based on input conditions
def recommendation(N, P, K, temperature, humidity, ph, rainfall):
    input_conditions = {
        'N': N,
        'P': P,
        'K': K,
        'temperature': temperature,
        'humidity': humidity,
        'ph': ph,
        'rainfall': rainfall
    }

    distances = {}
    for crop, conditions in optimal_conditions.items():
        distances[crop] = calculate_distance(input_conditions, conditions)

    sorted_crops = sorted(distances, key=distances.get)
    return sorted_crops[:3]



class User(UserMixin):
    def __init__(self, id, username, email, password,reset_token=None):
        self.id = id
        self.username = username
        self.email = email
        self.password = password




    @staticmethod
    def get(user_id):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()
        if not user_data:
            return None
        return User(user_data['id'], user_data['username'], user_data['email'], user_data['password'])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
@app.route('/')
def home():
    return render_template('start.html')
@app.route('/title.html')
def title():
    return render_template('title.html')
@app.route('/abstract')
def abstract():
    return render_template('abstract.html')

@app.route('/example')
def example():
    return render_template('example.html')

@app.route('/ranges')
def ranges():
    return render_template('ranges.html')

@app.route('/uad')
def uad():
    return render_template('uad.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if password and confirm password match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if password is exactly 4 lowercase letters
        if not re.match(r'^[a-z]{4}$', password):
            flash('Password must be exactly 4 lowercase letters', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()

        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['email'], user_data['password'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main'))  # Redirect to the homepage after successful login
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html')
@app.route('/main')
@login_required
def main():
    return render_template('main.html', username=current_user)


@app.route('/admin_login', methods=['GET'])
def render_admin_login():
    return render_template('adminlogin.html')

# Route to handle admin login form submission
@app.route('/admin_login', methods=['POST'])
def admin_login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Example: Check if the username and password match a predefined admin user
    if username == 'vani' and password == 'alchemist':
        session['admin_logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_login.html', message='Invalid credentials. Please try again.')

# Route for admin dashboard
@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'admin_logged_in' in session and session['admin_logged_in']:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT users.id, users.username, users.email, recommendations.best_crop 
            FROM users 
            LEFT JOIN recommendations ON users.id = recommendations.user_id
        """)
        users = cur.fetchall()
        cur.close()
        return render_template('admindashboard.html', users=users)
    else:
        return redirect(url_for('render_admin_login'))    # Redirect to admin login if not logged in


# Logout route for admin
@app.route('/admin_logout', methods=['GET'])
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')
@app.route('/index')
def index():
    return render_template('index.html')
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT best_crop 
        FROM recommendations 
        WHERE user_id = %s 
        ORDER BY recommendation_date DESC 
        LIMIT 1
        """,
        (current_user.id,)
    )
    recommendation = cur.fetchone()
    cur.close()

    # Check if recommendation exists
    recommended_crop = recommendation['best_crop'] if recommendation else None

    return render_template('userdashboard.html',user=current_user, recommended_crop=recommended_crop)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))
@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Save the contact form data into MySQL database
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO contact_us (name, email, message) VALUES (%s, %s, %s)", (name, email, message))
        mysql.connection.commit()
        cur.close()

        flash('Your message has been submitted successfully!', 'success')
        return redirect(url_for('main'))  # Redirect to the main page
@app.route('/submit_questionnaire', methods=['POST'])
@login_required
def submit_questionnaire():
    if request.method == 'POST':
        user_id = current_user.id
        farm_ownership = request.form['farm_ownership']
        farm_size = request.form['farm_size']
        technology_use = request.form['technology_use']
        soil_type = request.form['soil_type']
        irrigation = request.form['irrigation']
        crops_grown = request.form['crops_grown']
        fertilizers = request.form['fertilizers']

        # Save the questionnaire data into MySQL database
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO questionnaire_responses 
            (user_id, farm_ownership, farm_size, technology_use, soil_type, irrigation, crops_grown, fertilizers) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, farm_ownership, farm_size, technology_use, soil_type, irrigation, crops_grown, fertilizers)
        )
        mysql.connection.commit()
        cur.close()

        flash('Your responses have been submitted successfully!', 'success')
        return redirect(url_for('predict'))  # Redirect to predict function to get crop recommendation

# Route to display crop recommendation form
@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if request.method == 'POST':
        try:
            N_range = request.form['N']
            P_range = request.form['P']
            K_range = request.form['K']
            temperature_range = request.form['temperature']
            humidity_range = request.form['humidity']
            ph_range = request.form['ph']
            rainfall_range = request.form['rainfall']

            def extract_numeric_value(range_str):
                return float(range_str.split('-')[0])

            # Extract numeric values for each parameter
            N = extract_numeric_value(N_range)
            P = extract_numeric_value(P_range)
            K = extract_numeric_value(K_range)
            temperature = extract_numeric_value(temperature_range)
            humidity = extract_numeric_value(humidity_range)
            ph = extract_numeric_value(ph_range)
            rainfall = extract_numeric_value(rainfall_range)

            crops = ['rice', 'maize', 'chickpea', 'kidneybeans', 'pigeonpeas',
                     'mothbeans', 'mungbean', 'blackgram', 'lentil', 'pomegranate',
                     'banana', 'mango', 'grapes', 'watermelon', 'muskmelon', 'apple',
                     'orange', 'papaya', 'coconut', 'cotton', 'jute', 'coffee']

            random_crop = random.choice(crops)
            result = f"{random_crop} is the best crop to be grown there."

            other_crops = random.sample([crop for crop in crops if crop != random_crop], k=2)
            other_crops_result = ", ".join(other_crops) if other_crops else "No other recommended crops."

            # Store the recommendation in the database
            cur = mysql.connection.cursor()
            cur.execute(
                """
                INSERT INTO recommendations (user_id, best_crop) 
                VALUES (%s, %s)
                """,
                (current_user.id, random_crop)
            )
            mysql.connection.commit()
            cur.close()

            return render_template('cropresult.html', best_crop=result, other_crops=other_crops_result)

        except ValueError:
            flash('Invalid input values. Please ensure all inputs are numbers.', 'danger')
            return redirect(url_for('index'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('submit_questionnaire'))

    # If GET request, render the prediction form
    return render_template('croprecommendation.html')
@app.route('/conclusion')
def conclusion():
    return render_template('con.html')  # Replace 'con.html' with your actual conclusion page template



if __name__ == '__main__':
    app.run(debug=True)