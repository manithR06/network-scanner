from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Scan(db.Model):
    """One scan job — e.g. scanning 192.168.1.0/24"""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)   # IP or range
    # basic / full / vuln
    scan_type = db.Column(db.String(50), default='basic')
    # pending/running/done/failed
    status = db.Column(db.String(20), default='pending')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    total_hosts = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)

    # Relationship — one scan has many hosts
    hosts = db.relationship('Host', backref='scan',
                            lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_hosts': self.total_hosts,
            'risk_score': self.risk_score,
            'hosts': [h.to_dict() for h in self.hosts]
        }


class Host(db.Model):
    """One live host discovered during a scan"""
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    hostname = db.Column(db.String(200), nullable=True)
    os_name = db.Column(db.String(200), nullable=True)
    os_accuracy = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='up')
    # low/medium/high/critical
    risk_level = db.Column(db.String(20), default='low')
    risk_score = db.Column(db.Float, default=0.0)

    # Relationship — one host has many ports
    ports = db.relationship('Port', backref='host',
                            lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'os_name': self.os_name,
            'os_accuracy': self.os_accuracy,
            'status': self.status,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'ports': [p.to_dict() for p in self.ports]
        }


class Port(db.Model):
    """One open port on a host"""
    __tablename__ = 'ports'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')
    state = db.Column(db.String(20), default='open')
    service_name = db.Column(db.String(100), nullable=True)
    service_version = db.Column(db.String(200), nullable=True)
    risk_level = db.Column(db.String(20), default='low')

    def to_dict(self):
        return {
            'id': self.id,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'risk_level': self.risk_level
        }
