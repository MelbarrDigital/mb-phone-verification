from flask import Flask, render_template, request, redirect, url_for, send_file, send_from_directory, jsonify, flash, session
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberFormat, PhoneNumberType
import json
from datetime import datetime, timedelta
import os
import csv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re
import requests
import pandas as pd

# Secure secret key from environment or fallback for development
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key')
# Remember me session life
app.permanent_session_lifetime = timedelta(days=7)

USERS_FILE = '/tmp/users.json'
HISTORY_FILE = '/tmp/singleValidationHistory.json'
UPLOAD_FOLDER = '/tmp/uploads'
OUTPUT_FOLDER = '/tmp/output'
BULK_HISTORY_FILE = '/tmp/BulkValidationHistory.json'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def get_user(email):
    users = load_users()
    return next((u for u in users if u['email'].lower() == email.lower()), None)

def get_number_type_desc(ntype):
    return {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll-Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.SHARED_COST: "Shared Cost",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.UNKNOWN: "Unknown"
    }.get(ntype, 'Unknown')

def save_bulk_history(entry):
    if os.path.exists(BULK_HISTORY_FILE):
        with open(BULK_HISTORY_FILE, 'r') as f:
            history = json.load(f)
    else:
        history = []

    history.insert(0, entry)
    with open(BULK_HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

# Clean Number 
def clean_number(raw_number):
    if not raw_number:
        return ""

    raw_number = str(raw_number).strip()

    # Fix scientific notation (e.g., 4.48451E+11)
    try:
        if 'e' in raw_number.lower():
            raw_number = str(int(float(raw_number)))
    except:
        pass

    raw_number = raw_number.encode('ascii', 'ignore').decode()
    raw_number = raw_number.replace(' ', '')
    raw_number = re.sub(r'[^\d+]', '', raw_number)

    if raw_number.count('+') > 1:
        raw_number = raw_number.replace('+', '')
    elif raw_number.startswith('+'):
        plus = '+'
        raw_number = plus + raw_number[1:].replace('+', '')
    else:
        raw_number = raw_number.replace('+', '')

    return raw_number

# Load Hostory
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []

def save_history(entry):
    history = load_history()
    history.insert(0, entry)  # Insert latest at top
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def is_suspicious_number(national_number):
    last_four_zeros = national_number.endswith('0000')

    return (
        last_four_zeros
    )

# File Upload Allowed Functions
ALLOWED_EXTENSIONS = {'csv', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Login Pages
@app.route('/auth', methods=['GET'])
def auth_page():
    return render_template('auth.html')

# Login Backend
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember')  # Get the checkbox value

    users = load_users()
    user = next((u for u in users if u['email'].lower() == email.lower()), None)
    
    if user and check_password_hash(user['password'], password):
        session.permanent = bool(remember)  # If 'remember' is checked, make session permanent

        session['user'] = {
            'email': user['email'],
            'name': user.get('name', 'User'),
            'role': user['role'],
            'veriphone_access': user.get('veriphone_access', False),
            'credits': user.get('credits', 0)
        }
        user['last_login'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        save_users(users)

        return redirect(url_for('dashboard'))
    else:
        flash("Invalid credentials.")
        return redirect(url_for('auth_page'))

# Logout Backend Code
@app.route('/logout')
def logout():
    # Remove user information from the session
    session.pop('user', None)
    flash("Logged out successfully.")
    return redirect(url_for('auth_page'))

# Register
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    email = data.get('email')
    password = data.get('password')

    if get_user(email):
        flash("User already exists.")
        return redirect(url_for('auth_page'))

    new_user = {
        'email': email,
        'password': generate_password_hash(password),
        'veriphone_access': False,
        'veriphone_credits': 0,
        'role': 'local',
        'last_login': ""
    }

    users = load_users()
    users.append(new_user)
    save_users(users)

    flash("Registered successfully. Please log in.")
    return redirect(url_for('auth_page'))

# Load Veriphone Data
def load_veriphone_config():
    with open('veriphone_config.json', 'r') as f:
        return json.load(f)

def update_veriphone_credits(new_credits):
    config = load_veriphone_config()
    config['credits_left'] = new_credits
    config['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('veriphone_config.json', 'w') as f:
        json.dump(config, f, indent=2)



# User PRofile
@app.route('/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        # Update the user's name
        new_name = request.form.get('name')
        user_email = session['user']['email']

        users = load_users()
        for user in users:
            if user['email'].lower() == user_email.lower():
                user['name'] = new_name
                session['user']['name'] = new_name  # Update in session too
                break
        save_users(users)
        flash("Name updated successfully.")
        return redirect(url_for('account'))
    veriphone_config = {}
    if session['user']['role'] == 'admin':
        veriphone_config = load_veriphone_config()

    return render_template('account.html',veriphone_config=veriphone_config)

@app.route('/veriphone-admin', methods=['GET', 'POST'])
def veriphone_admin():
    if session['user']['role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    config = load_veriphone_config()

    if request.method == 'POST':
        config['api_key'] = request.form['api_key']
        config['plan'] = request.form['plan']
        config['monthly_limit'] = int(request.form['monthly_limit'])
        config['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('veriphone_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        flash("Veriphone configuration updated successfully.")
        return redirect(url_for('veriphone_admin'))

    return render_template('veriphone_admin.html', config=config)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        user_email = session['user']['email']
        users = load_users()

        for user in users:
            if user['email'].lower() == user_email.lower():
                if not check_password_hash(user['password'], current):
                    flash("Incorrect current password.")
                    return redirect(url_for('change_password'))
                if new != confirm:
                    flash("New passwords do not match.")
                    return redirect(url_for('change_password'))

                user['password'] = generate_password_hash(new)
                save_users(users)
                flash("Password updated successfully.")
                return redirect(url_for('account'))

        flash("User not found.")
        return redirect(url_for('change_password'))

    return render_template('change_password.html')

@app.before_request
def require_login():
    allowed_routes = ['auth_page', 'login', 'register', 'static']
    if request.endpoint not in allowed_routes and 'user' not in session:
        return redirect(url_for('auth_page'))

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# Create User
@app.route('/create-user-admin', methods=['GET', 'POST'])
def create_user_admin():
    if session['user']['role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    config = load_veriphone_config()
    available = config['credits_left']
    users = load_users()

    if request.method == 'POST':
        email = request.form['email'].lower()
        name = request.form['name']
        password = request.form['password']
        credits = int(request.form['credits'])
        access = request.form['veriphone_access'] == 'true'

        if get_user(email):
            flash("User already exists.")
            return redirect(url_for('create_user_admin'))

        if credits > available:
            flash("Assigned credits exceed available balance.")
            return redirect(url_for('create_user_admin'))

        new_user = {
            'email': email,
            'name': name,
            'password': generate_password_hash(password),
            'veriphone_access': access,
            'credits': credits,
            'role': 'local',
            'last_login': ''
        }

        users.append(new_user)
        save_users(users)

        # Deduct from available Veriphone pool
        config['credits_left'] -= credits
        config['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('veriphone_config.json', 'w') as f:
            json.dump(config, f, indent=2)

        flash("User created and credits assigned successfully.")
        return redirect(url_for('create_user_admin'))

    return render_template('create_user_admin.html', available_credits=config['credits_left'],users=users)

# Edit User
@app.route('/edit-user/<email>', methods=['GET', 'POST'])
def edit_user(email):
    if session['user']['role'] != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    users = load_users()
    user = next((u for u in users if u['email'].lower() == email.lower()), None)

    if not user:
        flash("User not found.")
        return redirect(url_for('create_user_admin'))

    if request.method == 'POST':
        user['name'] = request.form['name']
        user['credits'] = int(request.form['credits'])
        user['veriphone_access'] = request.form['veriphone_access'] == 'true'
        save_users(users)
        flash("User updated successfully.")
        return redirect(url_for('create_user_admin'))

    return render_template('edit_user.html', user=user)


@app.route('/dashboard')
def dashboard():
    # Load recent single validations
    if os.path.exists('singleValidationHistory.json'):
        with open('singleValidationHistory.json', 'r') as f:
            single_history = json.load(f)
    else:
        single_history = []

    # Load recent bulk validations
    if os.path.exists('BulkValidationHistory.json'):
        with open('BulkValidationHistory.json', 'r') as f:
            bulk_history = json.load(f)
    else:
        bulk_history = []

    # Remove deleted ones for dashboard view
    bulk_history = [item for item in bulk_history if item.get('Status', '').lower() != 'deleted']

    # Initialize counts
    total = 0
    valid = 0
    invalid = 0

    # Calculate last 7 days
    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)

    # From single history
    for record in single_history:
        try:
            timestamp = record.get('timestamp', '').strip()
            if timestamp:
                record_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                if record_time >= seven_days_ago:
                    total += 1
                    if record.get('valid'):
                        valid += 1
                    else:
                        invalid += 1
        except Exception as e:
            print(f"Error parsing single record: {e}")
            continue

    # From bulk summary
    for entry in bulk_history:
        try:
            entry_time_str = entry.get('DateTime', '').strip()
            if entry_time_str:
                entry_time = datetime.strptime(entry_time_str, '%Y-%m-%d %H:%M:%S')
                if entry_time >= seven_days_ago:
                    total += int(entry.get('Records', 0))
                    valid += int(entry.get('Valid', 0))
                    invalid += int(entry.get('Invalid', 0))
        except Exception as e:
            print(f"Error parsing bulk entry: {e}")
            continue
     # Calculate percentages
    valid_percentage = round((valid / total) * 100, 1) if total else 0
    invalid_percentage = round((invalid / total) * 100, 1) if total else 0

    return render_template(
        'dashboard.html',
        single_history=single_history,
        bulk_history=bulk_history,
        total_validations=total,
        total_valid=valid,
        total_invalid =invalid,
        valid_percentage=valid_percentage,
        invalid_percentage=invalid_percentage
    )

@app.route('/validate', methods=['GET', 'POST'])
def validate():
    result = None
    page = int(request.args.get('page', 1))
    per_page = 10

    full_history = load_history()
    total_pages = (len(full_history) + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    history = full_history[start:end]

    if request.method == 'POST':
        country = request.form['country']
        phone_input = request.form['phone']

        try:
            parsed_number = phonenumbers.parse(phone_input, country)
            actual_region = geocoder.region_code_for_number(parsed_number).upper()

            if actual_region != country.upper():
                raise ValueError("Invalid : Another Country Contact Number")

            is_valid = phonenumbers.is_valid_number(parsed_number)
            suspicious = is_suspicious_number(str(parsed_number.national_number))

            result = {
                'input': phone_input,
                'uploaded_country': country,
                'country': actual_region,
                'valid': is_valid and not suspicious,
                'region': geocoder.description_for_number(parsed_number, "en"),
                'carrier': carrier.name_for_number(parsed_number, "en"),
                'type': get_number_type_desc(phonenumbers.number_type(parsed_number)),
                'formatted': phonenumbers.format_number(parsed_number, PhoneNumberFormat.INTERNATIONAL),
                'intl': phonenumbers.format_number(parsed_number, PhoneNumberFormat.E164),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'valid_type': 'local'
            }

            save_history(result)

        except Exception as e:
            result = {
                'input': phone_input,
                'uploaded_country': country,
                'country': country,
                'valid': False,
                'region': '-',
                'carrier': '-',
                'type': '-',
                'formatted': '-',
                'intl': '-',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'valid_type': 'local',
                'error': str(e)
            }
            save_history(result)

        full_history = load_history()
        total_pages = (len(full_history) + per_page - 1) // per_page
        history = full_history[start:end]

    showing_start = start + 1 if full_history else 0
    showing_end = min(end, len(full_history))

    return render_template(
        'validate.html',
        result=result,
        history=history,
        page=page,
        pages=total_pages,
        showing_start=showing_start,
        showing_end=showing_end,
        total=len(full_history)
    )


@app.route('/bulk', methods=['GET', 'POST'])
def bulk():
    results = []
    page = int(request.args.get('page', 1))
    per_page = 10

    if request.method == 'POST':
        file = request.files.get('csvfile')
        if not file or file.filename == '':
            flash("No file selected.")
            return redirect(url_for('bulk'))

        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        file_ext = os.path.splitext(filename)[1].lower()
        try:
            if file_ext == '.csv':
                df = pd.read_csv(upload_path)
            elif file_ext in ['.xls', '.xlsx']:
                df = pd.read_excel(upload_path)
            else:
                flash("Unsupported file format. Upload CSV or Excel.")
                return redirect(url_for('bulk'))
        except Exception as e:
            flash(f"Error reading file: {e}")
            return redirect(url_for('bulk'))

        if df.shape[1] < 2:
            flash("File must have at least two columns: Number and Country.")
            return redirect(url_for('bulk'))

        has_domain = df.shape[1] >= 3
        df.columns = ['Number', 'Country'] + (['Domain'] if has_domain else [])

        output_data = []
        valid_count = 0
        invalid_count = 0

        for i, row in df.iterrows():
            raw_number = clean_number(str(row['Number']))
            region = str(row['Country']).strip()
            domain = row['Domain'] if has_domain else ''

            try:
                parse_region = None if raw_number.startswith('+') else region.upper()
                parsed = phonenumbers.parse(raw_number, parse_region)
                actual_region = geocoder.region_code_for_number(parsed).upper()

                if actual_region != region.upper():
                    raise ValueError("Another Country Contact Number")

                is_valid = phonenumbers.is_valid_number(parsed)
                suspicious = is_suspicious_number(parsed)

                region_desc = geocoder.description_for_number(parsed, 'en')
                provider = carrier.name_for_number(parsed, 'en')
                num_type = get_number_type_desc(number_type(parsed))
                formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

                result_type = 'Suspicious' if suspicious else 'Valid' if is_valid else 'Invalid'
                if result_type == 'Valid':
                    valid_count += 1
                else:
                    invalid_count += 1

                row_data = {
                    'Uploaded Number': raw_number,
                    'Uploaded Country': region,
                    'Company Domain': domain if has_domain else '',
                    'Valid/Invalid': result_type,
                    'Region': region_desc,
                    'Carrier': provider,
                    'Type': num_type,
                    'Formatted': formatted,
                    'International Format': intl
                }

                if i < 15:
                    results.append({
                        'input': raw_number,
                        'country': region,
                        'valid': result_type == 'Valid',
                        'region': region_desc,
                        'carrier': provider,
                        'type': num_type,
                        'formatted': formatted,
                        'intl': intl
                    })

                output_data.append(row_data)

            except Exception as e:
                invalid_count += 1
                row_data = {
                    'Uploaded Number': raw_number,
                    'Uploaded Country': region,
                    'Company Domain': domain if has_domain else '',
                    'Valid/Invalid': f"Error: {str(e)}",
                    'Region': '', 'Carrier': '', 'Type': '', 'Formatted': '', 'International Format': ''
                }
                output_data.append(row_data)

        # Save output as Excel
        output_df = pd.DataFrame(output_data)
        output_filename = f"validated_{os.path.splitext(filename)[0]}.xlsx"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        output_df.to_excel(output_path, index=False)

        save_bulk_history({
            "DateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "File Name": output_filename,
            "Records": valid_count + invalid_count,
            "Valid": valid_count,
            "Invalid": invalid_count,
            "Status": "active"
        })

        with open('latest_bulk_results.json', 'w') as f:
            json.dump(results, f)

        return redirect(url_for('bulk'))

    # After redirect: Load saved latest results if any
    if os.path.exists('latest_bulk_results.json'):
        with open('latest_bulk_results.json', 'r') as f:
            results = json.load(f)
        os.remove('latest_bulk_results.json')

    if os.path.exists(BULK_HISTORY_FILE):
        with open(BULK_HISTORY_FILE, 'r') as f:
            history = json.load(f)
    else:
        history = []

    active_history = [entry for entry in history if entry.get('Status') != 'deleted']
    total_pages = (len(active_history) + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    paginated_history = active_history[start:end]
    showing_start = start + 1 if active_history else 0
    showing_end = min(end, len(active_history))

    return render_template(
        'bulk.html',
        results=results,
        history=paginated_history,
        page=page,
        pages=total_pages,
        showing_start=showing_start,
        showing_end=showing_end,
        total=len(active_history)
    )

@app.route('/download_results')
def download_results():
    # just returns latest output file — enhance if needed
    files = sorted(os.listdir(OUTPUT_FOLDER), key=lambda x: os.path.getctime(os.path.join(OUTPUT_FOLDER, x)), reverse=True)
    if files:
        return send_from_directory(OUTPUT_FOLDER, files[0], as_attachment=True)
    return "No output files found", 404

@app.route('/download-history')
def download_history():
    history = load_history()
    csv_path = 'validation_history.csv'

    with open(csv_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Uploaded Number', 'Uploaded Country', 'Valid/Invalid',
            'Region', 'Carrier', 'Type', 'Formatted', 'International Format', 'Timestamp'
        ])
        for row in history:
            writer.writerow([
                row['input'], row['country'], 'Valid' if row['valid'] else 'Invalid',
                row['region'], row['carrier'], row['type'],
                row['formatted'], row['intl'], row['timestamp']
            ])

    return send_file(csv_path, as_attachment=True)

@app.route('/delete-history/<filename>', methods=['POST'])
def delete_history(filename):
    # Remove the actual files
    try:
        upload_file = os.path.join(UPLOAD_FOLDER, filename)
        output_file = os.path.join(OUTPUT_FOLDER, f"validated_{filename}")
        if os.path.exists(upload_file):
            os.remove(upload_file)
        if os.path.exists(output_file):
            os.remove(output_file)
    except Exception as e:
        print(f"Failed to delete files: {e}")

    # Mark as deleted in JSON
    if os.path.exists(BULK_HISTORY_FILE):
        with open(BULK_HISTORY_FILE, 'r') as f:
            history = json.load(f)
        for record in history:
            if record['File Name'] == filename:
                record['Status'] = 'deleted'
        with open(BULK_HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)

    return redirect(url_for('bulk'))

@app.route('/download-history-file/<filename>')
def download_history_file(filename):
    output_file = os.path.join(OUTPUT_FOLDER, f"validated_{filename}")
    if os.path.exists(output_file):
        return send_file(output_file, as_attachment=True)
    return "File not found", 404


if __name__ == '__main__':
    app.run(debug=True)

