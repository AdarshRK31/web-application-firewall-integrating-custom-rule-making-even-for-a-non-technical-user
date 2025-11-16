from datetime import datetime
from . import db

class Rule(db.Model):
    __tablename__ = 'rules'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    condition = db.Column(db.String(512), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # block, allow, alert
    pattern_type = db.Column(db.String(20), default='regex')  # plain / regex
    active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<Rule {self.id}: {self.description}>"

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)

    # store as DateTime for correctness; old string values remain readable
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    ip = db.Column(db.String(100))
    url = db.Column(db.String(1024))
    reason = db.Column(db.String(1024))

    # NEW columns (must match DB schema)
    action = db.Column(db.String(50))        # e.g. "block", "alert"
    severity = db.Column(db.Integer)        # numeric severity 0-100

    def __repr__(self):
        return f"<Log {self.id}: {self.reason}>"

class AttackPattern(db.Model):
    __tablename__ = 'attack_patterns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    regex = db.Column(db.String(1024), nullable=False)
    action = db.Column(db.String(50), default='block')
    reason = db.Column(db.String(255))
    category = db.Column(db.String(50))

    def __repr__(self):
        return f"<AttackPattern {self.name}: {self.category}>"
