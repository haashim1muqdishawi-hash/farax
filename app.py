import os
import uuid
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'farax-production-secret-key-change-this'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///farax.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    # ⚠️ CHANGE: Required for cross‑origin cookies (frontend on Netlify, backend on Render)
    SESSION_COOKIE_SAMESITE = 'None'
    SESSION_COOKIE_HTTPONLY = True
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

app = Flask(__name__)
app.config.from_object(Config)

# ⚠️ CHANGE: Replace 'https://faraxx.netlify.app/' with your actual Netlify domain
CORS(app,
     origins=[
         'https://faraxx.netlify.app/',      # 👈 YOUR NETLIFY DOMAIN
         'http://localhost:5000',
         'http://127.0.0.1:5000'
     ],
     supports_credentials=True)               # Required to send cookies

Talisman(app, content_security_policy=None)  # optional, adjust as needed
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# ========== MODELS ==========
# (unchanged – keep as is)
class User(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"user{uuid.uuid4().hex[:8]}")
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    recovery_hashes = db.Column(db.Text)  # JSON list of hashed secrets
    recovery_email = db.Column(db.String(120))
    profile_picture = db.Column(db.String(200))
    friends = db.Column(db.Text, default='[]')  # JSON list of user IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    default_duration = db.Column(db.Integer, default=1440)  # minutes
    default_visibility = db.Column(db.String(20), default='friends')

    def to_dict(self, include_private=False):
        data = {
            'id': self.id,
            'username': self.username,
            'displayName': self.display_name,
            'profilePicture': self.profile_picture,
            'friends': json.loads(self.friends) if self.friends else [],
            'createdAt': self.created_at.isoformat()
        }
        if include_private:
            data['recoveryEmail'] = self.recovery_email
            data['defaultDuration'] = self.default_duration
            data['defaultVisibility'] = self.default_visibility
        return data

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_recovery(self, secrets):
        hashed = [generate_password_hash(s) for s in secrets]
        self.recovery_hashes = json.dumps(hashed)

    def verify_recovery(self, secrets):
        if not self.recovery_hashes:
            return False
        stored = json.loads(self.recovery_hashes)
        if len(secrets) != len(stored):
            return False
        return all(check_password_hash(stored[i], secrets[i]) for i in range(len(secrets)))

class Post(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"post{uuid.uuid4().hex[:8]}")
    author_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    content_type = db.Column(db.String(20), default='text')
    media_url = db.Column(db.String(200))
    visibility = db.Column(db.String(20), default='public')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    reactions = db.Column(db.Text, default='{}')  # JSON object {emoji: [user_ids]}

    def to_dict(self):
        return {
            'id': self.id,
            'authorId': self.author_id,
            'content': self.content,
            'contentType': self.content_type,
            'mediaUrl': self.media_url,
            'visibility': self.visibility,
            'createdAt': self.created_at.isoformat(),
            'expiresAt': self.expires_at.isoformat(),
            'reactions': json.loads(self.reactions) if self.reactions else {}
        }

class Comment(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"cmt{uuid.uuid4().hex[:8]}")
    post_id = db.Column(db.String(32), db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.String(32), db.ForeignKey('comment.id'), nullable=True)
    author_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    mentions = db.Column(db.Text, default='[]')  # JSON list of user IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'postId': self.post_id,
            'parentId': self.parent_id,
            'authorId': self.author_id,
            'content': self.content,
            'mentions': json.loads(self.mentions) if self.mentions else [],
            'createdAt': self.created_at.isoformat()
        }

class Group(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"group{uuid.uuid4().hex[:8]}")
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    avatar = db.Column(db.String(10), default='🌿')
    admin_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    members = db.Column(db.Text, default='[]')  # JSON list of user IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.Column(db.Text, default='[]')  # JSON list of post dicts (ephemeral group posts)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'avatar': self.avatar,
            'admin': self.admin_id,
            'members': json.loads(self.members) if self.members else [],
            'createdAt': self.created_at.isoformat(),
            'posts': json.loads(self.posts) if self.posts else []
        }

class FriendRequest(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"req{uuid.uuid4().hex[:8]}")
    from_user = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    to_user = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'from': self.from_user,
            'to': self.to_user,
            'status': self.status,
            'createdAt': self.created_at.isoformat()
        }

class Notification(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: f"notif{uuid.uuid4().hex[:8]}")
    user_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'mention', 'reply', 'friend_request'
    from_user_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.String(32), db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.String(32), db.ForeignKey('comment.id'), nullable=True)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'fromUserId': self.from_user_id,
            'postId': self.post_id,
            'commentId': self.comment_id,
            'read': self.read,
            'createdAt': self.created_at.isoformat()
        }

# Create tables
with app.app_context():
    db.create_all()

# ========== HELPER FUNCTIONS ==========
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique = f"{uuid.uuid4().hex}_{filename}"
        path = os.path.join(Config.UPLOAD_FOLDER, unique)
        file.save(path)
        return f"/uploads/{unique}"
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None

# ========== ERROR HANDLER ==========
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(str(e))
    return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# ========== SCHEDULER FOR CLEANUP ==========
def cleanup_expired():
    now = datetime.utcnow()
    expired_posts = Post.query.filter(Post.expires_at <= now).all()
    for post in expired_posts:
        Comment.query.filter_by(post_id=post.id).delete()
        Notification.query.filter_by(post_id=post.id).delete()
        db.session.delete(post)
    cutoff = now - timedelta(days=7)
    FriendRequest.query.filter(FriendRequest.created_at <= cutoff).delete()
    cutoff_notif = now - timedelta(days=30)
    Notification.query.filter(Notification.created_at <= cutoff_notif).delete()
    db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_expired, 'interval', hours=1)
scheduler.start()

# ========== API ROUTES ==========
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_FOLDER, filename)

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    url = save_file(file)
    if url:
        return jsonify({'url': url})
    return jsonify({'error': 'Invalid file type'}), 400

# Auth endpoints
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.json
    username = data.get('username', '').strip()
    display_name = data.get('displayName', '').strip()
    password = data.get('password')
    recovery = data.get('recovery', [])
    recovery_email = data.get('recoveryEmail', '').strip()

    if not username or not display_name or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    user = User(username=username, display_name=display_name,
                recovery_email=recovery_email)
    user.set_password(password)
    if recovery and len(recovery) == 3:
        user.set_recovery(recovery)
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    return jsonify({'success': True, 'user': user.to_dict(include_private=True)})

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        return jsonify({'success': True, 'user': user.to_dict(include_private=True)})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/api/me')
@login_required
def get_current_user():
    user = get_current_user()
    if user:
        return jsonify({'user': user.to_dict(include_private=True)})
    return jsonify({'error': 'User not found'}), 404

# Users
@app.route('/api/users')
def get_users():
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]})

@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()})

@app.route('/api/users/<user_id>/posts')
def get_user_posts(user_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    query = Post.query.filter(
        Post.author_id == user_id,
        Post.expires_at > datetime.utcnow()
    )
    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({'posts': [p.to_dict() for p in posts.items], 'total': posts.total})

@app.route('/api/users/<user_id>/liked-posts')
@login_required
def get_liked_posts(user_id):
    user = get_current_user()
    if user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    all_posts = Post.query.filter(Post.expires_at > datetime.utcnow()).all()
    liked = []
    for p in all_posts:
        reactions = json.loads(p.reactions) if p.reactions else {}
        if any(user.id in users for users in reactions.values()):
            liked.append(p)
    liked.sort(key=lambda x: x.created_at, reverse=True)
    start = (page-1)*per_page
    end = start+per_page
    paginated = liked[start:end]
    return jsonify({'posts': [p.to_dict() for p in paginated], 'total': len(liked)})

# Posts
@app.route('/api/posts', methods=['GET'])
@login_required
def get_posts():
    current_user = get_current_user()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    query = Post.query.filter(Post.expires_at > datetime.utcnow())
    posts = query.order_by(Post.created_at.desc()).all()
    visible = []
    for p in posts:
        if p.visibility == 'public':
            visible.append(p)
        elif p.visibility == 'friends':
            friends = json.loads(current_user.friends) if current_user.friends else []
            if p.author_id == current_user.id or p.author_id in friends:
                visible.append(p)
        elif p.visibility == 'private':
            if p.author_id == current_user.id:
                visible.append(p)
    start = (page-1)*per_page
    end = start+per_page
    paginated = visible[start:end]
    return jsonify({'posts': [p.to_dict() for p in paginated], 'total': len(visible)})

@app.route('/api/posts', methods=['POST'])
@login_required
def create_post():
    data = request.json
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    visibility = data.get('visibility', 'public')
    duration_minutes = data.get('duration', 1440)
    media_url = data.get('mediaUrl')
    content_type = data.get('contentType', 'text')

    post = Post(
        author_id=session['user_id'],
        content=content,
        content_type=content_type,
        media_url=media_url,
        visibility=visibility,
        expires_at=datetime.utcnow() + timedelta(minutes=duration_minutes)
    )
    db.session.add(post)
    db.session.commit()
    return jsonify({'success': True, 'post': post.to_dict()})

@app.route('/api/posts/<post_id>/react', methods=['POST'])
@login_required
def react_to_post(post_id):
    data = request.json
    emoji = data.get('emoji')
    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    reactions = json.loads(post.reactions) if post.reactions else {}
    for e in list(reactions.keys()):
        if session['user_id'] in reactions[e]:
            reactions[e].remove(session['user_id'])
            if not reactions[e]:
                del reactions[e]
    if emoji:
        if emoji not in reactions:
            reactions[emoji] = []
        if session['user_id'] not in reactions[emoji]:
            reactions[emoji].append(session['user_id'])
    post.reactions = json.dumps(reactions)
    db.session.commit()
    return jsonify({'success': True, 'reactions': reactions})

@app.route('/api/posts/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    query = Comment.query.filter_by(post_id=post_id)
    comments = query.order_by(Comment.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({'comments': [c.to_dict() for c in comments.items], 'total': comments.total})

@app.route('/api/comments', methods=['POST'])
@login_required
def create_comment():
    data = request.json
    post_id = data.get('postId')
    content = data.get('content', '').strip()
    parent_id = data.get('parentId')
    mentions = data.get('mentions', [])

    if not content:
        return jsonify({'error': 'Comment cannot be empty'}), 400

    comment = Comment(
        post_id=post_id,
        parent_id=parent_id,
        author_id=session['user_id'],
        content=content,
        mentions=json.dumps(mentions)
    )
    db.session.add(comment)
    db.session.commit()

    for mentioned_user_id in mentions:
        if mentioned_user_id != session['user_id']:
            notif = Notification(
                user_id=mentioned_user_id,
                type='mention',
                from_user_id=session['user_id'],
                post_id=post_id,
                comment_id=comment.id
            )
            db.session.add(notif)

    if parent_id:
        parent = Comment.query.get(parent_id)
        if parent and parent.author_id != session['user_id']:
            notif = Notification(
                user_id=parent.author_id,
                type='reply',
                from_user_id=session['user_id'],
                post_id=post_id,
                comment_id=comment.id
            )
            db.session.add(notif)

    db.session.commit()
    return jsonify({'success': True, 'comment': comment.to_dict()})

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if not comment or comment.author_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'success': True})

# Friend requests
@app.route('/api/friend-requests', methods=['GET'])
@login_required
def get_friend_requests():
    pending = FriendRequest.query.filter_by(to_user=session['user_id'], status='pending').all()
    return jsonify({'requests': [r.to_dict() for r in pending]})

@app.route('/api/friend-requests', methods=['POST'])
@login_required
def send_friend_request():
    data = request.json
    to_user_id = data.get('userId')
    if to_user_id == session['user_id']:
        return jsonify({'error': 'Cannot send request to yourself'}), 400
    to_user = User.query.get(to_user_id)
    if not to_user:
        return jsonify({'error': 'User not found'}), 404
    current_user = get_current_user()
    friends = json.loads(current_user.friends) if current_user.friends else []
    if to_user_id in friends:
        return jsonify({'error': 'Already friends'}), 400
    existing = FriendRequest.query.filter_by(from_user=session['user_id'], to_user=to_user_id, status='pending').first()
    if existing:
        return jsonify({'error': 'Friend request already sent'}), 400

    req = FriendRequest(from_user=session['user_id'], to_user=to_user_id)
    db.session.add(req)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friend-requests/<request_id>', methods=['PUT'])
@login_required
def respond_friend_request(request_id):
    data = request.json
    action = data.get('action')
    req = FriendRequest.query.get(request_id)
    if not req or req.to_user != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    if action == 'accept':
        req.status = 'accepted'
        from_user = User.query.get(req.from_user)
        to_user = User.query.get(req.to_user)
        from_friends = json.loads(from_user.friends) if from_user.friends else []
        to_friends = json.loads(to_user.friends) if to_user.friends else []
        if req.from_user not in to_friends:
            to_friends.append(req.from_user)
        if req.to_user not in from_friends:
            from_friends.append(req.to_user)
        from_user.friends = json.dumps(from_friends)
        to_user.friends = json.dumps(to_friends)
    else:
        req.status = 'declined'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/<friend_id>', methods=['DELETE'])
@login_required
def remove_friend(friend_id):
    current_user = get_current_user()
    friends = json.loads(current_user.friends) if current_user.friends else []
    if friend_id not in friends:
        return jsonify({'error': 'Not friends'}), 400
    friends.remove(friend_id)
    current_user.friends = json.dumps(friends)

    other = User.query.get(friend_id)
    if other:
        other_friends = json.loads(other.friends) if other.friends else []
        if session['user_id'] in other_friends:
            other_friends.remove(session['user_id'])
            other.friends = json.dumps(other_friends)
    db.session.commit()
    return jsonify({'success': True})

# Groups
@app.route('/api/groups', methods=['GET'])
def get_groups():
    groups = Group.query.all()
    return jsonify({'groups': [g.to_dict() for g in groups]})

@app.route('/api/groups', methods=['POST'])
@login_required
def create_group():
    data = request.json
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    avatar = data.get('avatar', '🌿')
    if not name:
        return jsonify({'error': 'Group name required'}), 400

    group = Group(
        name=name,
        description=description,
        avatar=avatar,
        admin_id=session['user_id'],
        members=json.dumps([session['user_id']])
    )
    db.session.add(group)
    db.session.commit()
    return jsonify({'success': True, 'group': group.to_dict()})

@app.route('/api/groups/<group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    members = json.loads(group.members) if group.members else []
    if session['user_id'] not in members:
        members.append(session['user_id'])
        group.members = json.dumps(members)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    if group.admin_id == session['user_id']:
        return jsonify({'error': 'Admin cannot leave, transfer admin or delete group'}), 400
    members = json.loads(group.members) if group.members else []
    if session['user_id'] in members:
        members.remove(session['user_id'])
        group.members = json.dumps(members)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<group_id>/posts', methods=['POST'])
@login_required
def create_group_post(group_id):
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    members = json.loads(group.members) if group.members else []
    if session['user_id'] not in members:
        return jsonify({'error': 'You are not a member of this group'}), 403

    data = request.json
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content required'}), 400

    duration = data.get('duration', 1440)
    post = {
        'id': f"gpost{uuid.uuid4().hex[:8]}",
        'authorId': session['user_id'],
        'content': content,
        'contentType': data.get('contentType', 'text'),
        'mediaUrl': data.get('mediaUrl'),
        'createdAt': datetime.utcnow().isoformat(),
        'expiresAt': (datetime.utcnow() + timedelta(minutes=duration)).isoformat()
    }
    posts = json.loads(group.posts) if group.posts else []
    posts.append(post)
    group.posts = json.dumps(posts)
    db.session.commit()
    return jsonify({'success': True, 'post': post})

# Notifications
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    notifs = Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.created_at.desc()).all()
    return jsonify({'notifications': [n.to_dict() for n in notifs]})

@app.route('/api/notifications/<notification_id>/read', methods=['PUT'])
@login_required
def mark_notification_read(notification_id):
    notif = Notification.query.get(notification_id)
    if not notif or notif.user_id != session['user_id']:
        return jsonify({'error': 'Not found'}), 404
    notif.read = True
    db.session.commit()
    return jsonify({'success': True})

# Search
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify({'users': [], 'posts': [], 'groups': []})
    users = User.query.filter(
        (User.username.ilike(f'%{query}%')) | (User.display_name.ilike(f'%{query}%'))
    ).all()
    posts = Post.query.filter(
        Post.expires_at > datetime.utcnow(),
        Post.content.ilike(f'%{query}%')
    ).all()
    groups = Group.query.filter(
        (Group.name.ilike(f'%{query}%')) | (Group.description.ilike(f'%{query}%'))
    ).all()

    return jsonify({
        'users': [u.to_dict() for u in users],
        'posts': [p.to_dict() for p in posts],
        'groups': [g.to_dict() for g in groups]
    })

# Account management
@app.route('/api/user/delete-content', methods=['DELETE'])
@login_required
def delete_user_content():
    user_id = session['user_id']
    Post.query.filter_by(author_id=user_id).delete()
    Comment.query.filter_by(author_id=user_id).delete()
    FriendRequest.query.filter((FriendRequest.from_user == user_id) | (FriendRequest.to_user == user_id)).delete()
    Notification.query.filter_by(user_id=user_id).delete()
    groups = Group.query.all()
    for g in groups:
        members = json.loads(g.members) if g.members else []
        if user_id in members:
            members.remove(user_id)
            g.members = json.dumps(members)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/user/delete-account', methods=['DELETE'])
@login_required
def delete_account():
    user_id = session['user_id']
    delete_user_content()
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/api/user/profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    url = save_file(file)
    if not url:
        return jsonify({'error': 'Invalid file'}), 400
    user = get_current_user()
    user.profile_picture = url
    db.session.commit()
    return jsonify({'url': url})

@app.route('/api/user/settings', methods=['PUT'])
@login_required
def update_settings():
    data = request.json
    user = get_current_user()
    if 'defaultDuration' in data:
        user.default_duration = data['defaultDuration']
    if 'defaultVisibility' in data:
        user.default_visibility = data['defaultVisibility']
    db.session.commit()
    return jsonify({'success': True})

# ========== RUN APP ==========
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)