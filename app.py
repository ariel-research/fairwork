from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_security import Security, SQLAlchemyUserDatastore, current_user, auth_required, roles_required, roles_accepted, hash_password
from flask_wtf.csrf import CSRFProtect
from config import Config
from models import db, User, Role
from forms import ExtendedRegisterForm
import uuid

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, register_form=ExtendedRegisterForm)


def create_roles():
    """Create default roles if they don't exist."""
    roles = [
        {'name': 'admin', 'description': 'Administrator with full access'},
        {'name': 'user', 'description': 'Regular user'},
        {'name': 'moderator', 'description': 'Moderator with limited admin access'}
    ]
    for role_data in roles:
        if not user_datastore.find_role(role_data['name']):
            user_datastore.create_role(**role_data)
    db.session.commit()


def create_admin_user():
    """Create a default admin user if no admin exists."""
    admin_role = user_datastore.find_role('admin')
    if admin_role and not admin_role.users.first():
        admin = user_datastore.create_user(
            username='admin',
            email='admin@example.com',
            password=hash_password('adminpassword'),
            fs_uniquifier=str(uuid.uuid4()),
            roles=[admin_role]
        )
        db.session.commit()
        print("Default admin created: admin@example.com / adminpassword")


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/admin')
@auth_required()
@roles_required('admin')
def admin_dashboard():
    """Admin dashboard - only accessible by admins."""
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin/dashboard.html', users=users, roles=roles)


@app.route('/admin/users')
@auth_required()
@roles_required('admin')
def admin_users():
    """User management page."""
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)


@app.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
@auth_required()
@roles_required('admin')
def toggle_user_active(user_id):
    """Toggle user active status."""
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('You cannot deactivate your own account.', 'danger')
    else:
        user.active = not user.active
        db.session.commit()
        status = 'activated' if user.active else 'deactivated'
        flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/add-role/<int:role_id>', methods=['POST'])
@auth_required()
@roles_required('admin')
def add_user_role(user_id, role_id):
    """Add a role to a user."""
    user = User.query.get_or_404(user_id)
    role = Role.query.get_or_404(role_id)
    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        flash(f'Role {role.name} added to {user.username}.', 'success')
    else:
        flash(f'User already has role {role.name}.', 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/remove-role/<int:role_id>', methods=['POST'])
@auth_required()
@roles_required('admin')
def remove_user_role(user_id, role_id):
    """Remove a role from a user."""
    user = User.query.get_or_404(user_id)
    role = Role.query.get_or_404(role_id)

    # Prevent removing own admin role
    if user == current_user and role.name == 'admin':
        flash('You cannot remove your own admin role.', 'danger')
    elif role in user.roles:
        user.roles.remove(role)
        db.session.commit()
        flash(f'Role {role.name} removed from {user.username}.', 'success')
    else:
        flash(f'User does not have role {role.name}.', 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@auth_required()
@roles_required('admin')
def delete_user(user_id):
    """Delete a user."""
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('You cannot delete your own account.', 'danger')
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/moderator')
@auth_required()
@roles_accepted('admin', 'moderator')
def moderator_panel():
    """Moderator panel - accessible by admins and moderators."""
    return render_template('moderator/panel.html')


with app.app_context():
    db.create_all()
    create_roles()
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5032)
