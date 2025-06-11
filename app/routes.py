from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import check_password_hash, generate_password_hash
from .crypto import encrypt_password, decrypt_password
from .models import get_db_connection, get_user_aes_key
from .utils import generate_password
import re
import uuid, time, io, csv, base64, os, secrets

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user'] = username
            session['user_id'] = user['id']
            flash('Connexion réussie !', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Nom d’utilisateur ou mot de passe incorrect.', 'error')

    return render_template('login.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Adresse e-mail invalide.", "error")
            return redirect(url_for('main.register'))

        password_hash = generate_password_hash(password)
        raw_key = secrets.token_bytes(32)
        aes_key = base64.b64encode(raw_key).decode()

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password_hash, aes_key) VALUES (?, ?, ?, ?)',(username, email, password_hash, aes_key))
            conn.commit()
            conn.close()
            flash('Compte créé avec succès. Connecte-toi maintenant !', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            flash('Erreur : nom d’utilisateur déjà pris.', 'error')

    return render_template('register.html')

@main.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Veuillez vous connecter.", 'error')
        return redirect(url_for('main.login'))

    user_id = session['user_id']
    aes_key = get_user_aes_key(user_id)

    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM passwords WHERE user_id = ? ORDER BY id DESC',
        (user_id,)
    ).fetchall()
    conn.close()

    passwords = []
    for row in rows:
        decrypted = decrypt_password(row['encrypted_password'], row['iv'], aes_key).decode()

        passwords.append({
            'id': row['id'],
            'title': row['title'],
            'password': decrypted
        })

    return render_template('dashboard.html', username=session['user'], passwords=passwords)


@main.route('/logout')
def logout():
    session.clear()
    flash("Déconnecté avec succès.", 'success')
    return redirect(url_for('main.home'))


@main.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if 'user' not in session:
        flash("Veuillez vous connecter.", 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        title = request.form['title']
        plain_password = request.form['password']
        user_id = session['user_id']

        aes_key = get_user_aes_key(session['user_id'])
        encrypted, iv = encrypt_password(plain_password, aes_key)

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO passwords (user_id, title, encrypted_password, iv) VALUES (?, ?, ?, ?)',
            (user_id, title, encrypted, iv)
        )
        conn.commit()
        conn.close()

        flash("Mot de passe enregistré avec succès !", 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('add_password.html')


@main.route('/delete-password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'user' not in session:
        flash("Veuillez vous connecter.", 'error')
        return redirect(url_for('main.login'))

    user_id = session['user_id']

    conn = get_db_connection()

    row = conn.execute('SELECT * FROM passwords WHERE id = ? AND user_id = ?', (id, user_id)).fetchone()

    if row:
        conn.execute('DELETE FROM passwords WHERE id = ?', (id,))
        conn.commit()
        flash("Mot de passe supprimé avec succès.", 'success')
    else:
        flash("Action non autorisée ou mot de passe inexistant.", 'error')

    conn.close()
    return redirect(url_for('main.dashboard'))


@main.route('/generate-password')
def generate_password_api():
    length = int(request.args.get('length', 12))
    upper = request.args.get('upper', '1') == '1'
    digits = request.args.get('digits', '1') == '1'
    symbols = request.args.get('symbols', '1') == '1'

    password = generate_password(length, upper, digits, symbols)
    return jsonify({'password': password})


@main.route('/account')
def account():
    if 'user' not in session:
        flash("Veuillez vous connecter.", 'error')
        return redirect(url_for('main.login'))

    user_id = session['user_id']

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user:
        flash("Utilisateur introuvable.", 'error')
        return redirect(url_for('main.dashboard'))

    return render_template('account.html', username=user['username'], email=user['email'])


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash("Veuillez vous connecter.", "error")
        return redirect(url_for('main.login'))

    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(user['password_hash'], current_password):
            flash("Mot de passe actuel incorrect.", "error")
            return redirect(url_for('main.change_password'))

        if new_password != confirm_password:
            flash("Le nouveau mot de passe ne correspond pas à la confirmation.", "error")
            return redirect(url_for('main.change_password'))

        new_password_hash = generate_password_hash(new_password)
        conn = get_db_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
        conn.commit()
        conn.close()

        flash("Mot de passe modifié avec succès.", "success")
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')


@main.route('/share/<int:password_id>')
def share_password(password_id):
    if 'user_id' not in session:
        flash("Veuillez vous connecter.", "error")
        return redirect(url_for('main.login'))

    conn = get_db_connection()
    pw = conn.execute(
        'SELECT * FROM passwords WHERE id = ? AND user_id = ?',
        (password_id, session['user_id'])
    ).fetchone()

    if not pw:
        conn.close()
        flash("Mot de passe introuvable.", "error")
        return redirect(url_for('main.dashboard'))

    share_id = str(uuid.uuid4())
    timestamp = int(time.time())

    conn.execute(
        'INSERT INTO shared_links (id, password_id, created_at) VALUES (?, ?, ?)',
        (share_id, password_id, timestamp)
    )
    conn.commit()
    conn.close()

    share_url = url_for('main.view_shared_password', share_id=share_id, _external=True)
    flash(f"Voici le lien à partager : {share_url}", "success")
    return redirect(url_for('main.dashboard'))


@main.route('/shared/<share_id>')
def view_shared_password(share_id):
    conn = get_db_connection()
    shared = conn.execute(
        'SELECT * FROM shared_links WHERE id = ?', (share_id,)
    ).fetchone()

    if not shared:
        conn.close()
        return "Lien invalide ou expiré", 404

    if time.time() - shared['created_at'] > 600:
        conn.execute('DELETE FROM shared_links WHERE id = ?', (share_id,))
        conn.commit()
        conn.close()
        return "Lien expiré", 403

    pw_row = conn.execute(
        'SELECT title, encrypted_password, iv FROM passwords WHERE id = ?',
        (shared['password_id'],)
    ).fetchone()

    conn.execute('DELETE FROM shared_links WHERE id = ?', (share_id,))
    conn.commit()
    conn.close()

    if not pw_row:
        return "Mot de passe introuvable", 404

    from .crypto import decrypt_password
    aes_key = get_user_aes_key(session['user_id'])
    decrypted = decrypt_password(pw_row['encrypted_password'], pw_row['iv'], aes_key).decode('utf-8')


    return render_template('shared_password.html', title=pw_row['title'], password=decrypted)


@main.route('/export')
def export_passwords():
    if 'user_id' not in session:
        flash("Veuillez vous connecter.", "error")
        return redirect(url_for('main.login'))

    user_id = session['user_id']
    conn = get_db_connection()
    rows = conn.execute('SELECT title, encrypted_password, iv FROM passwords WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    from .crypto import decrypt_password

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Service', 'Mot de passe'])

    aes_key = get_user_aes_key(session['user_id'])

    for row in rows:
        decrypted = decrypt_password(row['encrypted_password'], row['iv'], aes_key).decode('utf-8')
        writer.writerow([row['title'], decrypted])

    output.seek(0)

    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=mes_mots_de_passe.csv"}
    )


@main.route('/import-passwords', methods=['POST'])
def import_passwords():
    if 'user_id' not in session:
        flash("Veuillez vous connecter.", "error")
        return redirect(url_for('main.login'))

    uploaded_file = request.files.get('file')
    if not uploaded_file:
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for('main.dashboard'))

    try:
        stream = io.StringIO(uploaded_file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        headers = next(csv_input)

        from .crypto import encrypt_password
        aes_key = get_user_aes_key(session['user_id'])

        conn = get_db_connection()
        user_id = session['user_id']
        count = 0

        for row in csv_input:
            if len(row) < 2:
                continue

            title, password = row[0], row[1]
            encrypted, iv = encrypt_password(password, aes_key)
            conn.execute(
                'INSERT INTO passwords (user_id, title, encrypted_password, iv) VALUES (?, ?, ?, ?)',
                (user_id, title, encrypted, iv)
            )
            count += 1

        conn.commit()
        conn.close()
        flash(f"{count} mot(s) de passe importé(s) avec succès.", "success")

    except Exception as e:
        flash("Erreur lors de l'importation du fichier.", "error")
        print(f"[Import Error] {e}")

    return redirect(url_for('main.dashboard'))