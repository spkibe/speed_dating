from flask import Flask, render_template, request, redirect, url_for, session
import pandas as pd
from data import get_likes_and_friendships

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Load your dataset (assuming may_22 is your pandas DataFrame)
may_22 = pd.read_csv('may_22.csv')  # Replace with your actual file
matches_df = get_likes_and_friendships(may_22)

# Mock user database (replace with SQLite or actual DB later)
users = {'nomkk@yahoo.com': 'password123'}  # Email: Password

@app.route('/')
def index():
    events = ['22 May 2019, 25-35yrs, London']  # Hardcoded for now, could be dynamic
    return render_template('index.html', events=events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users and users[email] == password:
            session['email'] = email
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email not in users:
            users[email] = password  # Add to mock DB
            return redirect(url_for('login'))
        return render_template('register.html', error='Email already registered')
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    user_matches = matches_df[(matches_df['Email address_x'] == email) | 
                              (matches_df['Email address_y'] == email)]
    
    events = user_matches['Event_x'].unique().tolist()
    selected_event = request.form.get('event', events[0] if events else None)
    
    filtered_matches = user_matches[user_matches['Event_x'] == selected_event]
    return render_template('dashboard.html', matches=filtered_matches.to_dict('records'), events=events, selected_event=selected_event)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=False)