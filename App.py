from flask import Flask, render_template, request, redirect, session, url_for,flash
import Diffie_hellman as dh
import Totp as totp

app = Flask(__name__)
app.secret_key = "super_secure_bifrost_key"

# In-memory database tracking users
users_db = {} 

@app.route('/')
def home():
    # If a user is fully logged in, show a welcome message
    if 'user' in session:
        return render_template('index.html', user= session['user'])
    return render_template('index.html', user=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        bob_public_key = int(request.form.get('bob_public_key'))
        
        alice_private = session.get('alice_private')
        shared_secret = dh.compute_shared_secret(bob_public_key, alice_private, dh.P)
        
        # Save credentials and the secret key to our database
        users_db[username] = {
            'password': password,
            'shared_secret': shared_secret
        }
        flash('Signup successful! Please log in now.', 'success')
        # Cleanup and redirect to home
        session.pop('alice_private', None)
        return redirect(url_for('home'))

    alice_private, alice_public = dh.generate_keys()
    session['alice_private'] = alice_private
    return render_template('signup.html', alice_public=alice_public)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users_db and users_db[username]['password'] == password:
            # Stage 1 Success: "Remember" the user but don't log them in fully yet
            session['pending_user'] = username
            return redirect(url_for('verify_totp'))
        return "Invalid Username or Password!"
        
    return render_template('login.html')

@app.route('/verify-totp', methods=['GET', 'POST'])
def verify_totp():
    # Security Check: Don't allow access to this page unless password was correct
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        username = session['pending_user']
        
        # Calculate what the code should be
        secret = users_db[username]['shared_secret']
        expected_otp = totp.generate_totp(secret)
        
        if user_otp == expected_otp:
            # Stage 2 Success: Finalize the login
            session['user'] = session.pop('pending_user')
            return redirect(url_for('home'))
        return "Invalid TOTP Code! <a href='/verify-totp'>Try again</a>"

    return render_template('verify_totp.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Listen on all network interfaces so other devices can connect
    app.run(host='0.0.0.0', port=5000, debug=True)