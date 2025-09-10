#!/usr/bin/env python3
"""
CPP Test Prep Platform - Complete Production Application
SECTION 1: Core Foundation and Setup
"""

import os
import json
import logging
import secrets
import hashlib
import datetime
import time
import math
import random
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps
from dataclasses import dataclass, asdict
from datetime import datetime as dt, timedelta
import uuid

# Flask and Extensions
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests

# Configuration Class
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cpp-platform-' + secrets.token_hex(32))
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    DATA_DIR = 'data'
    MAX_QUIZ_TIME = 3600  # 1 hour in seconds
    MAX_EXAM_TIME = 10800  # 3 hours in seconds
    PASS_THRESHOLD = 0.70
    SUBSCRIPTION_MONTHLY_PRICE = 29.99
    SUBSCRIPTION_6MONTH_PRICE = 149.99
    SUBSCRIPTION_ANNUAL_PRICE = 299.99

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cpp_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://api.openai.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com"
    return response

# Rate Limiting Store
rate_limit_store = {}

def rate_limit(max_requests: int, window_seconds: int):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            current_time = time.time()
            key = f"{client_ip}:{f.__name__}"
            
            if key not in rate_limit_store:
                rate_limit_store[key] = []
            
            # Clean old requests
            rate_limit_store[key] = [req_time for req_time in rate_limit_store[key] 
                                   if current_time - req_time < window_seconds]
            
            if len(rate_limit_store[key]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            rate_limit_store[key].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Data Models
@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    created_at: str
    subscription_status: str = 'inactive'
    subscription_plan: str = ''
    subscription_expires: str = ''
    stripe_customer_id: str = ''
    last_login: str = ''
    total_study_time: int = 0
    quiz_attempts: int = 0
    exam_attempts: int = 0
    streak_days: int = 0
    last_study_date: str = ''

@dataclass
class Question:
    id: str
    domain: str
    type: str  # multiple_choice, true_false, scenario
    question: str
    options: List[str]
    correct_answer: str
    explanation: str
    difficulty: int
    tags: List[str] = None

@dataclass
class Flashcard:
    id: str
    domain: str
    front: str
    back: str
    difficulty: int
    repetitions: int = 0
    ease_factor: float = 2.5
    interval: int = 1
    due_date: str = ''
    last_reviewed: str = ''
    times_studied: int = 0

@dataclass
class QuizAttempt:
    id: str
    user_id: str
    questions: List[str]
    answers: Dict[str, str]
    score: float
    domain_scores: Dict[str, float]
    completed_at: str
    time_taken: int
    quiz_type: str
    question_count: int
    timed_mode: bool = False

@dataclass
class ExamAttempt:
    id: str
    user_id: str
    questions: List[str]
    answers: Dict[str, str]
    score: float
    domain_scores: Dict[str, float]
    completed_at: str
    time_taken: int
    passed: bool
    question_count: int

@dataclass
class StudySession:
    id: str
    user_id: str
    session_type: str  # quiz, exam, flashcard, ai_tutor
    started_at: str
    completed_at: str = ''
    duration: int = 0
    items_studied: int = 0

# CPP Domain Configuration
CPP_DOMAINS = {
    'D1': {
        'name': 'Physical Security',
        'weight': 0.22,
        'description': 'Access control, perimeter security, surveillance, and physical protection measures'
    },
    'D2': {
        'name': 'Personnel Security', 
        'weight': 0.15,
        'description': 'Background investigations, security clearances, and personnel screening'
    },
    'D3': {
        'name': 'Information Systems Security',
        'weight': 0.09,
        'description': 'Network security, data protection, and cybersecurity measures'
    },
    'D4': {
        'name': 'Crisis Management',
        'weight': 0.11,
        'description': 'Emergency response, business continuity, and crisis communication'
    },
    'D5': {
        'name': 'Investigations',
        'weight': 0.16,
        'description': 'Investigation techniques, evidence handling, and case management'
    },
    'D6': {
        'name': 'Legal and Regulatory',
        'weight': 0.14,
        'description': 'Laws, regulations, compliance, and legal frameworks'
    },
    'D7': {
        'name': 'Professional and Ethical Responsibilities',
        'weight': 0.13,
        'description': 'Ethics, professional standards, and code of conduct'
    }
}

# Health Check Routes
@app.route('/health')
@app.route('/healthz')
@app.route('/ready')
def health_check():
    """Health check endpoint for deployment"""
    return jsonify({
        'status': 'healthy',
        'timestamp': dt.now().isoformat(),
        'service': 'CPP Test Prep Platform',
        'version': '2.0.0'
    })

"""
END OF SECTION 1: Core Foundation and Setup
"""
"""
CPP Test Prep Platform - Complete Production Application
SECTION 2: Data Management and Content Generation
"""

# Data Storage Manager
class DataManager:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._init_data_files()
    
    def _init_data_files(self):
        """Initialize data files if they don't exist"""
        files = {
            'users.json': {},
            'questions.json': self._get_default_questions(),
            'flashcards.json': self._get_default_flashcards(),
            'quiz_attempts.json': {},
            'exam_attempts.json': {},
            'study_sessions.json': {},
            'ai_conversations.json': {}
        }
        
        for filename, default_data in files.items():
            filepath = os.path.join(self.data_dir, filename)
            if not os.path.exists(filepath):
                self._save_data(filename, default_data)
    
    def _save_data(self, filename: str, data: Any):
        """Atomically save data to file"""
        filepath = os.path.join(self.data_dir, filename)
        temp_filepath = filepath + '.tmp'
        
        try:
            with open(temp_filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(temp_filepath, filepath)
        except Exception as e:
            logger.error(f"Error saving {filename}: {e}")
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
            raise
    
    def _load_data(self, filename: str) -> Any:
        """Load data from file"""
        filepath = os.path.join(self.data_dir, filename)
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"File {filename} not found, returning empty dict")
            return {}
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
            return {}
    
    # User Management
    def get_users(self) -> Dict[str, User]:
        """Get all users"""
        data = self._load_data('users.json')
        return {k: User(**v) for k, v in data.items()}
    
    def save_user(self, user: User):
        """Save user"""
        users = self._load_data('users.json')
        users[user.id] = asdict(user)
        self._save_data('users.json', users)
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        users = self.get_users()
        return users.get(user_id)
    
    # Question Management
    def get_questions(self) -> Dict[str, Question]:
        """Get all questions"""
        data = self._load_data('questions.json')
        return {k: Question(**v) for k, v in data.items()}
    
    def get_questions_by_domain(self, domain: str) -> List[Question]:
        """Get questions by domain"""
        questions = self.get_questions()
        return [q for q in questions.values() if q.domain == domain]
    
    def get_questions_by_type(self, question_type: str) -> List[Question]:
        """Get questions by type"""
        questions = self.get_questions()
        return [q for q in questions.values() if q.type == question_type]
    
    # Flashcard Management
    def get_flashcards(self) -> Dict[str, Flashcard]:
        """Get all flashcards"""
        data = self._load_data('flashcards.json')
        return {k: Flashcard(**v) for k, v in data.items()}
    
    def save_flashcard(self, flashcard: Flashcard):
        """Save flashcard"""
        flashcards = self._load_data('flashcards.json')
        flashcards[flashcard.id] = asdict(flashcard)
        self._save_data('flashcards.json', flashcards)
    
    def get_due_flashcards(self, user_id: str, domain: str = None) -> List[Flashcard]:
        """Get flashcards due for review"""
        flashcards = self.get_flashcards()
        now = dt.now()
        
        due_cards = []
        for card in flashcards.values():
            if domain and card.domain != domain:
                continue
                
            if card.due_date:
                try:
                    due_date = dt.fromisoformat(card.due_date)
                    if due_date <= now:
                        due_cards.append(card)
                except ValueError:
                    due_cards.append(card)
            else:
                due_cards.append(card)
        
        return due_cards
    
    # Quiz and Exam Attempts
    def save_quiz_attempt(self, attempt: QuizAttempt):
        """Save quiz attempt"""
        attempts = self._load_data('quiz_attempts.json')
        attempts[attempt.id] = asdict(attempt)
        self._save_data('quiz_attempts.json', attempts)
    
    def save_exam_attempt(self, attempt: ExamAttempt):
        """Save exam attempt"""
        attempts = self._load_data('exam_attempts.json')
        attempts[attempt.id] = asdict(attempt)
        self._save_data('exam_attempts.json', attempts)
    
    def get_user_quiz_attempts(self, user_id: str) -> List[QuizAttempt]:
        """Get user's quiz attempts"""
        data = self._load_data('quiz_attempts.json')
        attempts = []
        for attempt_data in data.values():
            if attempt_data['user_id'] == user_id:
                attempts.append(QuizAttempt(**attempt_data))
        return sorted(attempts, key=lambda x: x.completed_at, reverse=True)
    
    def get_user_exam_attempts(self, user_id: str) -> List[ExamAttempt]:
        """Get user's exam attempts"""
        data = self._load_data('exam_attempts.json')
        attempts = []
        for attempt_data in data.values():
            if attempt_data['user_id'] == user_id:
                attempts.append(ExamAttempt(**attempt_data))
        return sorted(attempts, key=lambda x: x.completed_at, reverse=True)
    
    # Study Session Tracking
    def save_study_session(self, session: StudySession):
        """Save study session"""
        sessions = self._load_data('study_sessions.json')
        sessions[session.id] = asdict(session)
        self._save_data('study_sessions.json', sessions)
    
    def get_user_study_sessions(self, user_id: str, days: int = 30) -> List[StudySession]:
        """Get user's recent study sessions"""
        data = self._load_data('study_sessions.json')
        cutoff_date = dt.now() - timedelta(days=days)
        
        sessions = []
        for session_data in data.values():
            if session_data['user_id'] == user_id:
                session_date = dt.fromisoformat(session_data['started_at'])
                if session_date >= cutoff_date:
                    sessions.append(StudySession(**session_data))
        
        return sorted(sessions, key=lambda x: x.started_at, reverse=True)
    
    # Content Generation Methods
    def _get_default_questions(self) -> Dict[str, dict]:
        """Generate comprehensive question bank"""
        questions = {}
        question_id = 1
        
        # Domain distribution based on CPP weights
        domain_counts = {
            'D1': 110,  # Physical Security (22%)
            'D2': 75,   # Personnel Security (15%)
            'D3': 45,   # Information Systems Security (9%)
            'D4': 55,   # Crisis Management (11%)
            'D5': 80,   # Investigations (16%)
            'D6': 70,   # Legal and Regulatory (14%)
            'D7': 65    # Professional and Ethical (13%)
        }
        
        for domain, count in domain_counts.items():
            # Generate multiple choice questions (50%)
            mc_count = int(count * 0.5)
            for i in range(mc_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'multiple_choice',
                    'question': self._generate_mc_question(domain, i),
                    'options': self._generate_mc_options(domain, i),
                    'correct_answer': self._generate_mc_options(domain, i)[0],
                    'explanation': self._generate_explanation(domain, i, 'mc'),
                    'difficulty': random.randint(1, 5),
                    'tags': self._generate_tags(domain)
                }
                question_id += 1
            
            # Generate true/false questions (25%)
            tf_count = int(count * 0.25)
            for i in range(tf_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'true_false',
                    'question': self._generate_tf_question(domain, i),
                    'options': ['True', 'False'],
                    'correct_answer': 'True' if i % 2 == 0 else 'False',
                    'explanation': self._generate_explanation(domain, i, 'tf'),
                    'difficulty': random.randint(1, 5),
                    'tags': self._generate_tags(domain)
                }
                question_id += 1
            
            # Generate scenario questions (25%)
            scenario_count = count - mc_count - tf_count
            for i in range(scenario_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'scenario',
                    'question': self._generate_scenario_question(domain, i),
                    'options': self._generate_scenario_options(domain, i),
                    'correct_answer': self._generate_scenario_options(domain, i)[0],
                    'explanation': self._generate_explanation(domain, i, 'scenario'),
                    'difficulty': random.randint(3, 5),
                    'tags': self._generate_tags(domain)
                }
                question_id += 1
        
        return questions
    
    def _generate_mc_question(self, domain: str, index: int) -> str:
        """Generate multiple choice questions by domain"""
        templates = {
            'D1': [
                "What is the most effective method for controlling access to a secured facility?",
                "Which type of barrier provides the best perimeter security for high-value assets?",
                "What is the recommended minimum illumination level for security lighting?",
                "Which access control method provides the highest level of security?",
                "What is the primary purpose of a mantrap entry system?",
                "Which physical security measure is most effective against forced entry?",
                "What is the optimal placement for surveillance cameras?",
                "Which type of lock provides the highest security rating?",
                "What is the purpose of security glazing in physical protection?",
                "Which alarm system component is most critical for detection?"
            ],
            'D2': [
                "What is the most critical component of a personnel security program?",
                "Which background investigation type is required for top secret clearance?",
                "What is the primary purpose of security awareness training?",
                "Which method is most effective for detecting insider threats?",
                "What is the recommended frequency for security clearance renewals?",
                "Which factor is most important in personnel screening?",
                "What is the purpose of continuous monitoring programs?",
                "Which interview technique is most effective for security screening?",
                "What is the standard for security clearance adjudication?",
                "Which document is required for personnel security determination?"
            ],
            'D3': [
                "What is the most effective method for securing database systems?",
                "Which encryption standard is recommended for protecting sensitive data?",
                "What is the primary purpose of network segmentation?",
                "Which authentication method provides the strongest security?",
                "What is the recommended frequency for security patch updates?",
                "Which firewall configuration provides optimal protection?",
                "What is the purpose of intrusion detection systems?",
                "Which backup strategy ensures data availability?",
                "What is the standard for wireless network security?",
                "Which access control model is most appropriate for classified systems?"
            ],
            'D4': [
                "What is the first priority during a security incident?",
                "Which communication method is most reliable during emergencies?",
                "What is the primary purpose of a business continuity plan?",
                "Which factor is most critical in crisis decision-making?",
                "What is the recommended structure for an incident response team?",
                "Which evacuation procedure is most effective?",
                "What is the purpose of emergency notification systems?",
                "Which recovery strategy minimizes business disruption?",
                "What is the standard for crisis communication?",
                "Which training method is most effective for emergency response?"
            ],
            'D5': [
                "What is the most important principle of evidence collection?",
                "Which interview technique is most effective for gathering information?",
                "What is the primary purpose of surveillance operations?",
                "Which documentation standard is required for legal proceedings?",
                "What is the recommended approach for conducting background investigations?",
                "Which forensic procedure ensures evidence integrity?",
                "What is the purpose of chain of custody documentation?",
                "Which investigation method is most thorough?",
                "What is the standard for witness testimony?",
                "Which analytical technique is most reliable?"
            ],
            'D6': [
                "What is the primary purpose of security policies and procedures?",
                "Which legal concept is most relevant to security operations?",
                "What is the recommended approach for handling legal compliance?",
                "Which documentation is required for regulatory audits?",
                "What is the most important consideration in contract security?",
                "Which law governs privacy protection?",
                "What is the purpose of regulatory compliance programs?",
                "Which legal standard applies to security operations?",
                "What is the requirement for data protection?",
                "Which contract provision is most critical?"
            ],
            'D7': [
                "What is the most important ethical principle in security practice?",
                "Which professional standard guides security practitioner conduct?",
                "What is the primary purpose of continuing education requirements?",
                "Which ethical consideration is paramount in investigations?",
                "What is the recommended approach for handling conflicts of interest?",
                "Which professional obligation is most important?",
                "What is the purpose of professional certification?",
                "Which ethical guideline governs confidentiality?",
                "What is the standard for professional development?",
                "Which code of conduct applies to security professionals?"
            ]
        }
        
        domain_templates = templates.get(domain, ["Generic security question"])
        return domain_templates[index % len(domain_templates)]
    
    def _generate_mc_options(self, domain: str, index: int) -> List[str]:
        """Generate multiple choice options"""
        option_sets = [
            ["Multi-layered security approach", "Single point of control", "Technology-only solution", "Manual verification only"],
            ["Integrated system design", "Isolated components", "Centralized management", "Distributed control"],
            ["Risk-based methodology", "Compliance-focused approach", "Cost-effective solution", "Maximum security regardless of cost"],
            ["Proactive prevention", "Reactive response", "Detective measures", "Corrective actions"],
            ["Comprehensive documentation", "Minimal paperwork", "Verbal instructions", "Informal procedures"],
            ["Continuous monitoring", "Periodic reviews", "Annual assessments", "One-time implementation"],
            ["Professional expertise", "Automated systems", "Vendor solutions", "Internal resources"],
            ["Standardized procedures", "Customized approaches", "Flexible guidelines", "Strict protocols"]
        ]
        return option_sets[index % len(option_sets)]
    
    def _generate_tf_question(self, domain: str, index: int) -> str:
        """Generate true/false questions"""
        templates = {
            'D1': [
                "Perimeter security should always include multiple layers of protection.",
                "Video surveillance can completely replace the need for security guards.",
                "Access control systems should log all entry and exit attempts.",
                "Physical barriers are more important than electronic security measures.",
                "Security lighting must be maintained at consistent levels.",
                "Visitor management systems are optional for most facilities.",
                "Emergency exits should be monitored but never restricted.",
                "Security glazing provides protection against both impact and ballistics."
            ],
            'D2': [
                "Background investigations are required for all employees with security access.",
                "Security clearances never expire once granted.",
                "Insider threats pose a greater risk than external threats.",
                "Security awareness training should be conducted annually.",
                "Continuous monitoring is required for all cleared personnel.",
                "Personal interviews are mandatory for all security clearances.",
                "Foreign contacts must be reported by cleared personnel.",
                "Financial difficulties can affect security clearance eligibility."
            ],
            'D3': [
                "Encryption is necessary for all data transmission.",
                "Network firewalls provide complete protection against cyber attacks.",
                "Multi-factor authentication significantly improves security.",
                "Security patches should be applied immediately upon release.",
                "Wireless networks require additional security measures.",
                "Data classification is essential for information protection.",
                "Backup systems must be tested regularly.",
                "Access controls should follow the principle of least privilege."
            ],
            'D4': [
                "Life safety is always the top priority in crisis situations.",
                "Crisis management plans should be tested regularly.",
                "Communication systems should have backup capabilities.",
                "Decision-making authority should be centralized during crises.",
                "Emergency procedures must be clearly documented.",
                "Business continuity planning is optional for small organizations.",
                "Recovery time objectives should be realistic and achievable.",
                "Crisis teams require specialized training."
            ],
            'D5': [
                "Evidence chain of custody must be maintained at all times.",
                "Surveillance operations require legal authorization.",
                "Witness interviews should be recorded whenever possible.",
                "Investigation reports must be objective and factual.",
                "Forensic procedures must follow established protocols.",
                "Digital evidence requires special handling procedures.",
                "Investigation findings should be peer reviewed.",
                "Documentation standards vary by jurisdiction."
            ],
            'D6': [
                "Security policies must comply with applicable laws and regulations.",
                "Legal counsel should be involved in security policy development.",
                "Regulatory compliance is optional for private organizations.",
                "Contract security services must meet the same standards as in-house security.",
                "Privacy laws apply to all security operations.",
                "Compliance audits should be conducted regularly.",
                "Legal requirements vary by industry and location.",
                "Documentation is critical for demonstrating compliance."
            ],
            'D7': [
                "Professional ethics override organizational policies.",
                "Continuing education is essential for security professionals.",
                "Conflicts of interest must be disclosed and managed.",
                "Professional certification demonstrates competency.",
                "Ethical guidelines are universally applicable.",
                "Professional development is a personal responsibility.",
                "Code of conduct violations should be reported.",
                "Ethical decision-making requires careful consideration."
            ]
        }
        
        domain_templates = templates.get(domain, ["Generic true/false question"])
        return domain_templates[index % len(domain_templates)]
    
    def _generate_scenario_question(self, domain: str, index: int) -> str:
        """Generate scenario-based questions"""
        scenarios = {
            'D1': [
                "A company is experiencing repeated security breaches at their main entrance. Employees are allowing unauthorized visitors to enter by holding doors open. What is the most effective solution?",
                "During a security assessment, you discover that the parking garage has poor lighting and multiple blind spots. What should be your primary recommendation?",
                "An office building has experienced several thefts from employee workspaces during business hours. What security measure would be most appropriate?",
                "A manufacturing facility needs to protect against both external threats and internal theft. What comprehensive approach should be implemented?"
            ],
            'D2': [
                "An employee with security clearance is showing signs of financial distress and has been asking colleagues about classified projects outside their area. What action should be taken?",
                "A new contractor needs access to sensitive areas but their background investigation is still pending. How should this situation be handled?",
                "During a routine security interview, an employee reveals unreported foreign contacts. What is the appropriate response?",
                "A cleared employee is exhibiting unusual behavior and colleagues are concerned about potential substance abuse. What steps should be taken?"
            ],
            'D3': [
                "Your organization's network has been compromised and sensitive data may have been accessed. What is your immediate priority?",
                "Employees are reporting suspicious emails that appear to be phishing attempts. What is the most appropriate response?",
                "A critical server has failed and the backup system is not responding. What should be the first action?",
                "Unauthorized software has been discovered on several workstations. What security measures should be implemented?"
            ],
            'D4': [
                "During a fire evacuation, some employees are refusing to leave their workstations to save important files. How should security personnel respond?",
                "A bomb threat has been received via phone with specific details about the device location. What is the appropriate immediate action?",
                "A severe weather warning has been issued and the facility may need to shelter in place. What should be the first priority?",
                "A medical emergency has occurred in a secure area during a critical meeting. How should the situation be managed?"
            ],
            'D5': [
                "During an investigation of theft, you discover evidence that implicates a senior manager. How should you proceed?",
                "A witness to a security incident is reluctant to provide information due to fear of retaliation. What is the best approach?",
                "Critical evidence has been found but the chain of custody may have been compromised. What action should be taken?",
                "An investigation reveals that security procedures were not followed, potentially affecting the case. How should this be addressed?"
            ],
            'D6': [
                "Your organization is subject to a regulatory audit and investigators are requesting access to security logs. What should be your primary concern?",
                "A contract security guard has violated company policy but claims they were following orders from their supervisor. How should this be addressed?",
                "New privacy regulations have been enacted that may affect your security procedures. What should be your first step?",
                "A legal dispute has arisen regarding security practices and your organization may face liability. What action should be taken?"
            ],
            'D7': [
                "You discover that a colleague is falsifying security reports to avoid additional work. What is the most appropriate action?",
                "A client is asking you to perform activities that may violate professional ethical standards. How should you respond?",
                "Your supervisor is pressuring you to ignore a security violation to avoid negative publicity. What should you do?",
                "You witness unethical behavior by a fellow security professional. What is your professional obligation?"
            ]
        }
        
        domain_scenarios = scenarios.get(domain, ["Generic scenario question"])
        return domain_scenarios[index % len(domain_scenarios)]
    
    def _generate_scenario_options(self, domain: str, index: int) -> List[str]:
        """Generate scenario answer options"""
        option_sets = [
            ["Implement a comprehensive solution addressing root causes", "Apply quick temporary fixes", "Escalate to senior management immediately", "Continue monitoring the situation"],
            ["Follow established procedures and protocols", "Take immediate action based on judgment", "Consult with legal counsel first", "Document and report to authorities"],
            ["Prioritize safety and security above all else", "Focus on maintaining business operations", "Balance competing interests carefully", "Seek guidance from subject matter experts"],
            ["Conduct thorough investigation before acting", "Take immediate corrective action", "Seek additional approval or authorization", "Implement interim protective measures"]
        ]
        return option_sets[index % len(option_sets)]
    
    def _generate_explanation(self, domain: str, index: int, question_type: str) -> str:
        """Generate detailed explanations for answers"""
        explanations = {
            'D1': "Physical security requires a layered approach combining multiple protective measures. The solution must address the specific threat while maintaining operational effectiveness and cost efficiency.",
            'D2': "Personnel security decisions must balance security requirements with individual rights and due process. All actions should follow established procedures and involve appropriate authorities.",
            'D3': "Information systems security requires immediate response to threats while maintaining system integrity and availability. Procedures must be documented and tested regularly.",
            'D4': "Crisis management prioritizes life safety while maintaining effective leadership and communication. Plans must be flexible enough to address various scenarios.",
            'D5': "Investigations must maintain evidence integrity and follow legal requirements. Objectivity and thoroughness are essential for credible results.",
            'D6': "Legal and regulatory compliance requires understanding current requirements and maintaining proper documentation. Professional guidance is often necessary.",
            'D7': "Professional ethics require putting public safety and professional standards above personal or organizational interests. Ethical dilemmas should be addressed through proper channels."
        }
        return explanations.get(domain, "This answer follows established security principles and best practices in the field.")
    
    def _generate_tags(self, domain: str) -> List[str]:
        """Generate relevant tags for questions"""
        tag_sets = {
            'D1': ['access_control', 'perimeter_security', 'surveillance', 'physical_barriers', 'lighting'],
            'D2': ['clearances', 'screening', 'investigations', 'insider_threat', 'training'],
            'D3': ['cybersecurity', 'data_protection', 'network_security', 'encryption', 'access_control'],
            'D4': ['emergency_response', 'business_continuity', 'crisis_communication', 'incident_management'],
            'D5': ['investigations', 'evidence', 'forensics', 'interviews', 'documentation'],
            'D6': ['compliance', 'regulations', 'legal', 'policies', 'contracts'],
            'D7': ['ethics', 'professional_standards', 'certification', 'development', 'conduct']
        }
        return tag_sets.get(domain, ['security', 'cpp'])
    
    def _get_default_flashcards(self) -> Dict[str, dict]:
        """Generate comprehensive flashcard set"""
        flashcards = {}
        card_id = 1
        
        # Domain-based flashcard distribution
        domain_cards = {
            'D1': 40, 'D2': 30, 'D3': 20, 'D4': 25,
            'D5': 30, 'D6': 25, 'D7': 25
        }
        
        for domain, count in domain_cards.items():
            for i in range(count):
                flashcards[str(card_id)] = {
                    'id': str(card_id),
                    'domain': domain,
                    'front': self._generate_flashcard_front(domain, i),
                    'back': self._generate_flashcard_back(domain, i),
                    'difficulty': random.randint(1, 5),
                    'repetitions': 0,
                    'ease_factor': 2.5,
                    'interval': 1,
                    'due_date': dt.now().isoformat(),
                    'last_reviewed': '',
                    'times_studied': 0
                }
                card_id += 1
        
        return flashcards
    
    def _generate_flashcard_front(self, domain: str, index: int) -> str:
        """Generate flashcard fronts by domain"""
        fronts = {
            'D1': [
                "Defense in Depth", "CPTED", "Access Control", "Perimeter Security", "Intrusion Detection",
                "Video Surveillance", "Security Lighting", "Physical Barriers", "Lock Classifications", "Key Management",
                "Mantrap Systems", "Security Glazing", "Alarm Systems", "Guard Services", "Visitor Management",
                "Asset Protection", "Facility Security", "Environmental Design", "Security Hardware", "Patrol Procedures"
            ],
            'D2': [
                "Security Clearance Levels", "Background Investigations", "Insider Threat", "Security Awareness",
                "Personnel Screening", "Continuous Monitoring", "Access Termination", "Security Training",
                "Clearance Adjudication", "Foreign Influence", "Financial Considerations", "Personal Conduct",
                "Security Violations", "Reporting Requirements", "Security Education", "Counterintelligence"
            ],
            'D3': [
                "Network Security", "Encryption Standards", "Access Controls", "Vulnerability Management",
                "Incident Response", "Data Classification", "Backup Procedures", "Security Monitoring",
                "Firewall Configuration", "Intrusion Detection", "Malware Protection", "Security Patches",
                "Wireless Security", "Database Security", "Application Security", "Security Architecture"
            ],
            'D4': [
                "Crisis Management", "Emergency Response", "Business Continuity", "Disaster Recovery",
                "Incident Command", "Communication Plans", "Evacuation Procedures", "Risk Assessment",
                "Emergency Planning", "Crisis Communication", "Recovery Planning", "Threat Assessment",
                "Emergency Operations", "Continuity Planning", "Crisis Leadership", "Response Coordination"
            ],
            'D5': [
                "Evidence Handling", "Chain of Custody", "Investigation Techniques", "Interview Methods",
                "Surveillance Operations", "Documentation Standards", "Legal Procedures", "Report Writing",
                "Forensic Analysis", "Witness Interviews", "Case Management", "Investigation Planning",
                "Evidence Collection", "Digital Forensics", "Investigation Ethics", "Fact Finding"
            ],
            'D6': [
                "Legal Compliance", "Regulatory Requirements", "Contract Law", "Privacy Laws",
                "Employment Law", "Liability Issues", "Professional Standards", "Audit Procedures",
                "Regulatory Frameworks", "Legal Documentation", "Compliance Programs", "Legal Risk",
                "Statutory Requirements", "Contractual Obligations", "Legal Remedies", "Due Diligence"
            ],
            'D7': [
                "Professional Ethics", "Code of Conduct", "Continuing Education", "Professional Development",
                "Conflict of Interest", "Confidentiality", "Professional Certification", "Best Practices",
                "Ethical Decision Making", "Professional Responsibility", "Industry Standards", "Competency",
                "Professional Integrity", "Ethical Guidelines", "Professional Growth", "Standards of Practice"
            ]
        }
        
        domain_fronts = fronts.get(domain, ["Generic Term"])
        return domain_fronts[index % len(domain_fronts)]
    
    def _generate_flashcard_back(self, domain: str, index: int) -> str:
        """Generate flashcard backs by domain"""
        backs = {
            'D1': [
                "Multiple layers of security controls to protect assets through redundant protection measures",
                "Crime Prevention Through Environmental Design - using design to reduce crime opportunities",
                "Methods and systems to regulate who can access facilities, areas, or information",
                "Security measures implemented at the boundary of protected areas or facilities",
                "Systems and procedures designed to detect unauthorized access attempts or security breaches"
            ],
            'D2': [
                "Confidential, Secret, and Top Secret - levels of security clearance based on potential damage",
                "Comprehensive process of verifying individual backgrounds, character, and suitability for access",
                "Security risk posed by individuals with authorized access to facilities or information",
                "Educational programs designed to help personnel recognize and respond to security threats",
                "Systematic process of evaluating personnel qualifications and suitability for positions"
            ],
            'D3': [
                "Protection of computer networks and information systems from cyber threats and attacks",
                "Cryptographic methods and algorithms used to protect data confidentiality and integrity",
                "Systems and procedures that restrict access to authorized users and approved activities",
                "Systematic process of identifying, assessing, and addressing security weaknesses and threats",
                "Organized approach to detecting, analyzing, and responding to security incidents"
            ],
            'D4': [
                "Coordinated organizational response to emergency situations and critical incidents",
                "Immediate actions and procedures taken during emergency situations to protect life and property",
                "Plans and procedures to maintain essential operations during and after disruptions",
                "Process of restoring normal operations and recovering from disasters or major incidents",
                "Structured approach to managing emergency response operations and resources"
            ],
            'D5': [
                "Proper procedures and protocols for collecting, preserving, and handling physical evidence",
                "Documentation system that tracks evidence handling from collection through court proceedings",
                "Systematic methods and approaches for gathering information and establishing facts",
                "Structured approaches and techniques for questioning witnesses, suspects, and sources",
                "Covert observation and monitoring activities to gather intelligence and evidence"
            ],
            'D6': [
                "Adherence to applicable laws, regulations, and legal requirements in security operations",
                "Legal standards, rules, and requirements that organizations must follow and implement",
                "Legal principles and agreements governing contractual relationships and obligations",
                "Legal regulations and requirements designed to protect individual privacy rights",
                "Legal principles governing workplace relationships, rights, and responsibilities"
            ],
            'D7': [
                "Moral principles and standards governing professional conduct in security practice",
                "Standards of behavior and conduct expected from security professionals",
                "Ongoing learning and training requirements for maintaining professional competency",
                "Activities and initiatives designed to enhance professional knowledge, skills, and abilities",
                "Situations where personal interests may compromise professional judgment or duties"
            ]
        }
        
        domain_backs = backs.get(domain, ["Generic Definition"])
        return domain_backs[index % len(domain_backs)]

# Initialize Data Manager
data_manager = DataManager(app.config['DATA_DIR'])

"""
END OF SECTION 2: Data Management and Content Generation
"""
"""
CPP Test Prep Platform - Complete Production Application
SECTION 3: Core Systems and Algorithms
"""

# Spaced Repetition Algorithm (SM-2 Enhanced)
class SpacedRepetition:
    @staticmethod
    def calculate_next_review(flashcard: Flashcard, quality: int) -> Flashcard:
        """
        Calculate next review date based on enhanced SM-2 algorithm
        Quality: 1 (total blackout) to 5 (perfect response)
        """
        if quality < 3:
            # Reset for difficult cards
            flashcard.repetitions = 0
            flashcard.interval = 1
        else:
            if flashcard.repetitions == 0:
                flashcard.interval = 1
            elif flashcard.repetitions == 1:
                flashcard.interval = 6
            else:
                flashcard.interval = round(flashcard.interval * flashcard.ease_factor)
            
            flashcard.repetitions += 1
        
        # Update ease factor
        flashcard.ease_factor = max(1.3, flashcard.ease_factor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02)))
        
        # Set next review date
        flashcard.due_date = (dt.now() + timedelta(days=flashcard.interval)).isoformat()
        flashcard.last_reviewed = dt.now().isoformat()
        flashcard.times_studied += 1
        
        return flashcard

# Progress Analytics Engine
class ProgressAnalytics:
    @staticmethod
    def calculate_overall_progress(user_id: str) -> Dict[str, Any]:
        """Calculate comprehensive progress metrics for user"""
        quiz_attempts = data_manager.get_user_quiz_attempts(user_id)
        exam_attempts = data_manager.get_user_exam_attempts(user_id)
        study_sessions = data_manager.get_user_study_sessions(user_id)
        
        if not quiz_attempts and not exam_attempts:
            return {
                'overall_score': 0,
                'domain_scores': {domain: 0 for domain in CPP_DOMAINS.keys()},
                'progress_percentage': 0,
                'study_streak': 0,
                'weak_domains': [],
                'strong_domains': [],
                'total_study_time': 0,
                'avg_session_length': 0,
                'recent_performance_trend': 'stable',
                'recommendation': 'Start with practice quizzes to assess your knowledge level'
            }
        
        # Calculate domain scores
        domain_scores = {}
        domain_attempt_counts = {}
        
        for domain in CPP_DOMAINS.keys():
            domain_attempts = [att for att in quiz_attempts + exam_attempts if domain in att.domain_scores]
            domain_attempt_counts[domain] = len(domain_attempts)
            
            if domain_attempts:
                # Weight recent attempts more heavily
                weighted_scores = []
                for i, attempt in enumerate(domain_attempts[-10:]):  # Last 10 attempts
                    weight = 1 + (i * 0.1)  # More recent = higher weight
                    weighted_scores.append(attempt.domain_scores[domain] * weight)
                
                if weighted_scores:
                    domain_scores[domain] = sum(weighted_scores) / sum(range(1, len(weighted_scores) + 1))
                else:
                    domain_scores[domain] = 0
            else:
                domain_scores[domain] = 0
        
        # Calculate overall score
        overall_score = sum(domain_scores.values()) / len(domain_scores) if domain_scores else 0
        progress_percentage = min(100, overall_score * 100)
        
        # Calculate study streak
        study_streak = ProgressAnalytics._calculate_study_streak(user_id)
        
        # Identify weak and strong domains
        sorted_domains = sorted(domain_scores.items(), key=lambda x: x[1])
        weak_domains = [domain for domain, score in sorted_domains[:3] if score < 0.6 and domain_attempt_counts[domain] > 0]
        strong_domains = [domain for domain, score in sorted_domains[-3:] if score >= 0.8 and domain_attempt_counts[domain] > 0]
        
        # Calculate study statistics
        total_study_time = sum(session.duration for session in study_sessions)
        avg_session_length = total_study_time / len(study_sessions) if study_sessions else 0
        
        # Calculate performance trend
        performance_trend = ProgressAnalytics._calculate_performance_trend(quiz_attempts + exam_attempts)
        
        return {
            'overall_score': overall_score,
            'domain_scores': domain_scores,
            'domain_attempt_counts': domain_attempt_counts,
            'progress_percentage': progress_percentage,
            'study_streak': study_streak,
            'weak_domains': weak_domains,
            'strong_domains': strong_domains,
            'total_study_time': total_study_time,
            'avg_session_length': avg_session_length,
            'recent_performance_trend': performance_trend,
            'recommendation': ProgressAnalytics._generate_recommendation(domain_scores, overall_score, study_streak)
        }
    
    @staticmethod
    def _calculate_study_streak(user_id: str) -> int:
        """Calculate consecutive days of study activity"""
        attempts = data_manager.get_user_quiz_attempts(user_id) + data_manager.get_user_exam_attempts(user_id)
        study_sessions = data_manager.get_user_study_sessions(user_id, days=365)
        
        # Combine all study activities
        study_dates = set()
        for attempt in attempts:
            date = dt.fromisoformat(attempt.completed_at).date()
            study_dates.add(date)
        
        for session in study_sessions:
            date = dt.fromisoformat(session.started_at).date()
            study_dates.add(date)
        
        if not study_dates:
            return 0
        
        # Calculate streak
        sorted_dates = sorted(study_dates, reverse=True)
        streak = 0
        today = dt.now().date()
        
        # Check if studied today or yesterday (allow for timezone differences)
        if sorted_dates[0] >= today - timedelta(days=1):
            streak = 1
            current_date = sorted_dates[0]
            
            for date in sorted_dates[1:]:
                if (current_date - date).days == 1:
                    streak += 1
                    current_date = date
                else:
                    break
        
        return streak
    
    @staticmethod
    def _calculate_performance_trend(attempts: List) -> str:
        """Calculate performance trend over recent attempts"""
        if len(attempts) < 3:
            return 'insufficient_data'
        
        # Get last 10 attempts
        recent_attempts = sorted(attempts, key=lambda x: x.completed_at)[-10:]
        scores = [att.score for att in recent_attempts]
        
        if len(scores) < 3:
            return 'stable'
        
        # Calculate trend using simple linear regression
        n = len(scores)
        x_vals = list(range(n))
        x_mean = sum(x_vals) / n
        y_mean = sum(scores) / n
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, scores))
        denominator = sum((x - x_mean) ** 2 for x in x_vals)
        
        if denominator == 0:
            return 'stable'
        
        slope = numerator / denominator
        
        if slope > 0.02:
            return 'improving'
        elif slope < -0.02:
            return 'declining'
        else:
            return 'stable'
    
    @staticmethod
    def _generate_recommendation(domain_scores: Dict[str, float], overall_score: float, study_streak: int) -> str:
        """Generate personalized study recommendations"""
        if overall_score < 0.4:
            return "Focus on building fundamental knowledge. Start with flashcards and basic practice quizzes."
        elif overall_score < 0.6:
            weak_domains = [domain for domain, score in domain_scores.items() if score < 0.5]
            if weak_domains:
                domain_names = [CPP_DOMAINS[d]['name'] for d in weak_domains[:2]]
                return f"Target your weak areas: {' and '.join(domain_names)}. Use focused practice quizzes."
            return "Continue building knowledge across all domains with mixed practice."
        elif overall_score < 0.75:
            if study_streak < 3:
                return "Establish a consistent daily study routine. You're making good progress!"
            return "You're ready for longer practice sessions and mock exams. Keep up the momentum!"
        else:
            return "Excellent progress! Focus on full-length mock exams to build test-taking endurance."

# Authentication and Session Management
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        user = data_manager.get_user_by_id(session['user_id'])
        
        if not user or user.subscription_status != 'active':
            flash('An active subscription is required to access this feature.', 'warning')
            return redirect(url_for('billing'))
        
        # Check subscription expiry
        if user.subscription_expires:
            try:
                expires = dt.fromisoformat(user.subscription_expires)
                if expires < dt.now():
                    user.subscription_status = 'expired'
                    data_manager.save_user(user)
                    flash('Your subscription has expired. Please renew to continue.', 'warning')
                    return redirect(url_for('billing'))
            except ValueError:
                pass
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        user = data_manager.get_user_by_id(session['user_id'])
        if not user or user.username != 'admin':
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

# Utility Functions
def generate_session_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def hash_password(password: str) -> str:
    """Hash password securely"""
    return generate_password_hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return check_password_hash(password_hash, password)

def get_current_user() -> Optional[User]:
    """Get current logged-in user"""
    if 'user_id' not in session:
        return None
    return data_manager.get_user_by_id(session['user_id'])

def update_user_activity(user_id: str, activity_type: str, duration: int = 0):
    """Update user activity and study streak"""
    user = data_manager.get_user_by_id(user_id)
    if not user:
        return
    
    today = dt.now().date().isoformat()
    
    # Update last study date and streak
    if user.last_study_date != today:
        if user.last_study_date:
            last_date = dt.fromisoformat(user.last_study_date).date()
            if (dt.now().date() - last_date).days == 1:
                user.streak_days += 1
            else:
                user.streak_days = 1
        else:
            user.streak_days = 1
        
        user.last_study_date = today
    
    # Update total study time
    user.total_study_time += duration
    
    # Save updated user
    data_manager.save_user(user)
    
    # Create study session record
    session_id = str(uuid.uuid4())
    study_session = StudySession(
        id=session_id,
        user_id=user_id,
        session_type=activity_type,
        started_at=dt.now().isoformat(),
        completed_at=dt.now().isoformat(),
        duration=duration,
        items_studied=1
    )
    data_manager.save_study_session(study_session)

def validate_email(email: str) -> bool:
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def generate_quiz_questions(domain: str = '', question_types: List[str] = None, 
                          difficulty_levels: List[int] = None, count: int = 25) -> List[Question]:
    """Generate quiz questions based on criteria"""
    all_questions = data_manager.get_questions()
    
    # Filter questions
    filtered_questions = []
    for question in all_questions.values():
        # Filter by domain
        if domain and question.domain != domain:
            continue
        
        # Filter by type
        if question_types and question.type not in question_types:
            continue
        
        # Filter by difficulty
        if difficulty_levels and question.difficulty not in difficulty_levels:
            continue
        
        filtered_questions.append(question)
    
    # Return random selection
    if len(filtered_questions) <= count:
        return filtered_questions
    
    return random.sample(filtered_questions, count)

def generate_exam_questions(question_count: int = 100) -> List[Question]:
    """Generate exam questions with proper domain distribution"""
    all_questions = data_manager.get_questions()
    questions_by_domain = {domain: [] for domain in CPP_DOMAINS.keys()}
    
    # Group questions by domain
    for question in all_questions.values():
        questions_by_domain[question.domain].append(question)
    
    # Select questions proportionally by domain weights
    selected_questions = []
    
    for domain, domain_info in CPP_DOMAINS.items():
        domain_questions = questions_by_domain[domain]
        target_count = int(question_count * domain_info['weight'])
        
        if len(domain_questions) >= target_count:
            selected = random.sample(domain_questions, target_count)
            selected_questions.extend(selected)
        else:
            # If not enough questions in domain, take all available
            selected_questions.extend(domain_questions)
    
    # If we don't have enough questions, fill with random questions
    if len(selected_questions) < question_count:
        remaining_count = question_count - len(selected_questions)
        remaining_questions = [q for q in all_questions.values() if q not in selected_questions]
        
        if remaining_questions:
            additional = random.sample(remaining_questions, min(remaining_count, len(remaining_questions)))
            selected_questions.extend(additional)
    
    # Shuffle final list
    random.shuffle(selected_questions)
    return selected_questions[:question_count]

def calculate_domain_scores(questions: List[Question], answers: Dict[str, str]) -> Dict[str, float]:
    """Calculate scores by domain"""
    domain_stats = {domain: {'correct': 0, 'total': 0} for domain in CPP_DOMAINS.keys()}
    
    for question in questions:
        user_answer = answers.get(question.id, '')
        is_correct = user_answer == question.correct_answer
        
        domain_stats[question.domain]['total'] += 1
        if is_correct:
            domain_stats[question.domain]['correct'] += 1
    
    # Calculate percentages
    domain_scores = {}
    for domain, stats in domain_stats.items():
        if stats['total'] > 0:
            domain_scores[domain] = stats['correct'] / stats['total']
        else:
            domain_scores[domain] = 0
    
    return domain_scores

def format_time_duration(seconds: int) -> str:
    """Format time duration in human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

def get_study_statistics(user_id: str) -> Dict[str, Any]:
    """Get comprehensive study statistics for user"""
    quiz_attempts = data_manager.get_user_quiz_attempts(user_id)
    exam_attempts = data_manager.get_user_exam_attempts(user_id)
    study_sessions = data_manager.get_user_study_sessions(user_id, days=90)
    
    # Calculate statistics
    total_attempts = len(quiz_attempts) + len(exam_attempts)
    total_questions = sum(att.question_count for att in quiz_attempts + exam_attempts)
    
    if quiz_attempts:
        avg_quiz_score = sum(att.score for att in quiz_attempts) / len(quiz_attempts)
        best_quiz_score = max(att.score for att in quiz_attempts)
    else:
        avg_quiz_score = 0
        best_quiz_score = 0
    
    if exam_attempts:
        avg_exam_score = sum(att.score for att in exam_attempts) / len(exam_attempts)
        best_exam_score = max(att.score for att in exam_attempts)
        passed_exams = len([att for att in exam_attempts if att.passed])
    else:
        avg_exam_score = 0
        best_exam_score = 0
        passed_exams = 0
    
    total_study_time = sum(session.duration for session in study_sessions)
    
    return {
        'total_attempts': total_attempts,
        'total_questions': total_questions,
        'quiz_attempts': len(quiz_attempts),
        'exam_attempts': len(exam_attempts),
        'avg_quiz_score': avg_quiz_score,
        'best_quiz_score': best_quiz_score,
        'avg_exam_score': avg_exam_score,
        'best_exam_score': best_exam_score,
        'passed_exams': passed_exams,
        'total_study_time': total_study_time,
        'avg_session_time': total_study_time / len(study_sessions) if study_sessions else 0
    }

"""
END OF SECTION 3: Core Systems and Algorithms
"""
"""
CPP Test Prep Platform - Complete Production Application
SECTION 4: Template Engine and User Interface System
"""

class TemplateEngine:
    """Complete template engine with advanced features and responsive design"""
    
    @staticmethod
    def _login_template(context: dict) -> str:
        """Login page template"""
        return TemplateEngine._base_template({
            **context,
            'title': 'Login - CPP Test Prep',
            'show_nav': False,
            'content': '''
            <div class="row justify-content-center">
                <div class="col-md-6 col-lg-5">
                    <div class="card-custom">
                        <div class="card-body p-5">
                            <div class="text-center mb-4">
                                <i class="fas fa-shield-alt text-primary" style="font-size: 3rem;"></i>
                                <h2 class="mt-3 mb-1">Welcome Back</h2>
                                <p class="text-muted">Sign in to continue your CPP preparation</p>
                            </div>
                            
                            <form method="POST" novalidate>
                                <div class="mb-3">
                                    <label for="username" class="form-label fw-semibold">Username or Email</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                                        <input type="text" class="form-control" id="username" name="username" 
                                               placeholder="Enter your username or email" required>
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="password" class="form-label fw-semibold">Password</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" id="password" name="password" 
                                               placeholder="Enter your password" required>
                                        <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </div>
                                
                                <div class="d-grid mb-3">
                                    <button type="submit" class="btn-custom">
                                        <i class="fas fa-sign-in-alt me-2"></i>Sign In
                                    </button>
                                </div>
                                
                                <div class="text-center">
                                    <p class="mb-0">Don't have an account? 
                                        <a href="/register" class="text-decoration-none fw-semibold">Register here</a>
                                    </p>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                document.getElementById('togglePassword').addEventListener('click', function() {
                    const password = document.getElementById('password');
                    const icon = this.querySelector('i');
                    
                    if (password.type === 'password') {
                        password.type = 'text';
                        icon.classList.remove('fa-eye');
                        icon.classList.add('fa-eye-slash');
                    } else {
                        password.type = 'password';
                        icon.classList.remove('fa-eye-slash');
                        icon.classList.add('fa-eye');
                    }
                });
            </script>
            '''
        })
    
    @staticmethod
    def _register_template(context: dict) -> str:
        """Registration page template"""
        return TemplateEngine._base_template({
            **context,
            'title': 'Register - CPP Test Prep',
            'show_nav': False,
            'content': '''
            <div class="row justify-content-center">
                <div class="col-md-6 col-lg-5">
                    <div class="card-custom">
                        <div class="card-body p-5">
                            <div class="text-center mb-4">
                                <i class="fas fa-user-plus text-primary" style="font-size: 3rem;"></i>
                                <h2 class="mt-3 mb-1">Create Account</h2>
                                <p class="text-muted">Join thousands preparing for the CPP exam</p>
                            </div>
                            
                            <form method="POST" novalidate>
                                <div class="mb-3">
                                    <label for="username" class="form-label fw-semibold">Username</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                                        <input type="text" class="form-control" id="username" name="username" 
                                               placeholder="Choose a username" required>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="email" class="form-label fw-semibold">Email Address</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                        <input type="email" class="form-control" id="email" name="email" 
                                               placeholder="Enter your email" required>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="password" class="form-label fw-semibold">Password</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" id="password" name="password" 
                                               placeholder="Create a password" minlength="8" required>
                                        <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                    <div class="form-text">Must be at least 8 characters long</div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="confirm_password" class="form-label fw-semibold">Confirm Password</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" id="confirm_password" 
                                               name="confirm_password" placeholder="Confirm your password" required>
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="terms" required>
                                        <label class="form-check-label" for="terms">
                                            I agree to the <a href="/terms" class="text-decoration-none">Terms of Service</a> 
                                            and <a href="/privacy" class="text-decoration-none">Privacy Policy</a>
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="d-grid mb-3">
                                    <button type="submit" class="btn-custom">
                                        <i class="fas fa-user-plus me-2"></i>Create Account
                                    </button>
                                </div>
                                
                                <div class="text-center">
                                    <p class="mb-0">Already have an account? 
                                        <a href="/login" class="text-decoration-none fw-semibold">Sign in here</a>
                                    </p>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                document.getElementById('togglePassword').addEventListener('click', function() {
                    const password = document.getElementById('password');
                    const icon = this.querySelector('i');
                    
                    if (password.type === 'password') {
                        password.type = 'text';
                        icon.classList.remove('fa-eye');
                        icon.classList.add('fa-eye-slash');
                    } else {
                        password.type = 'password';
                        icon.classList.remove('fa-eye-slash');
                        icon.classList.add('fa-eye');
                    }
                });
                
                // Password confirmation validation
                document.getElementById('confirm_password').addEventListener('input', function() {
                    const password = document.getElementById('password').value;
                    const confirmPassword = this.value;
                    
                    if (password !== confirmPassword) {
                        this.setCustomValidity('Passwords do not match');
                    } else {
                        this.setCustomValidity('');
                    }
                });
            </script>
            '''
        })
    
    @staticmethod
    def _dashboard_template(context: dict) -> str:
        """Dashboard template with comprehensive metrics"""
        user = context['user']
        progress = context['progress']
        domains = context['domains']
        
        # Build domain performance cards
        domain_cards = ""
        for domain_id, domain_info in domains.items():
            score = progress['domain_scores'][domain_id]
            score_percent = int(score * 100)
            attempt_count = progress.get('domain_attempt_counts', {}).get(domain_id, 0)
            
            performance_color = "success" if score >= 0.8 else "warning" if score >= 0.6 else "danger"
            performance_text = "Excellent" if score >= 0.8 else "Good" if score >= 0.6 else "Needs Work"
            
            domain_cards += f'''
            <div class="col-md-6 col-lg-4 mb-3">
                <div class="card-custom h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <h6 class="card-title mb-0">{domain_info['name']}</h6>
                            <span class="badge bg-{performance_color}">{performance_text}</span>
                        </div>
                        <div class="progress mb-2" style="height: 10px;">
                            <div class="progress-bar bg-{performance_color}" role="progressbar" 
                                 style="width: {score_percent}%" aria-valuenow="{score_percent}" 
                                 aria-valuemin="0" aria-valuemax="100"></div>
                        </div>
                        <div class="d-flex justify-content-between">
                            <small class="text-muted">{score_percent}% mastery</small>
                            <small class="text-muted">{attempt_count} attempts</small>
                        </div>
                    </div>
                </div>
            </div>
            '''
        
        # Performance trend indicator
        trend = progress.get('recent_performance_trend', 'stable')
        trend_icon = "fa-arrow-up text-success" if trend == 'improving' else "fa-arrow-down text-danger" if trend == 'declining' else "fa-minus text-secondary"
        trend_text = "Improving" if trend == 'improving' else "Declining" if trend == 'declining' else "Stable"
        
        content = f'''
        <div class="row">
            <div class="col-12 mb-4">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h1 class="mb-1">Welcome back, {user.username}!</h1>
                        <p class="text-muted mb-0">Ready to continue your CPP preparation?</p>
                    </div>
                    <div class="text-end">
                        <div class="d-flex align-items-center">
                            <i class="fas {trend_icon} me-2"></i>
                            <span class="fw-semibold">{trend_text}</span>
                        </div>
                        <small class="text-muted">Performance Trend</small>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Key Metrics Row -->
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon text-primary">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <div class="stat-number text-primary">{int(progress['progress_percentage'])}%</div>
                    <div class="stat-label">Overall Progress</div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon text-warning">
                        <i class="fas fa-fire"></i>
                    </div>
                    <div class="stat-number text-warning">{progress['study_streak']}</div>
                    <div class="stat-label">Day Streak</div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon text-success">
                        <i class="fas fa-trophy"></i>
                    </div>
                    <div class="stat-number text-success">{user.quiz_attempts}</div>
                    <div class="stat-label">Quiz Attempts</div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon text-info">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="stat-number text-info">{progress['total_study_time'] // 3600:.0f}h</div>
                    <div class="stat-label">Study Time</div>
                </div>
            </div>
        </div>
        
        <!-- Progress Visualization -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card-custom">
                    <div class="card-body text-center">
                        <h5 class="card-title mb-4">Overall Mastery</h5>
                        <div class="progress-circle">
                            <svg width="200" height="200" viewBox="0 0 200 200">
                                <circle cx="100" cy="100" r="80" fill="none" stroke="#e2e8f0" stroke-width="12"/>
                                <circle cx="100" cy="100" r="80" fill="none" stroke="#3b82f6" stroke-width="12"
                                        stroke-dasharray="{progress['progress_percentage'] * 5.03} 503"
                                        stroke-linecap="round"/>
                            </svg>
                            <div class="progress-text">{int(progress['progress_percentage'])}%</div>
                        </div>
                        <p class="text-muted mt-3">{progress['recommendation']}</p>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card-custom">
                    <div class="card-body">
                        <h5 class="card-title mb-4">Quick Actions</h5>
                        <div class="d-grid gap-2">
                            <a href="/quiz" class="btn-custom text-decoration-none">
                                <i class="fas fa-question-circle me-2"></i>Start Practice Quiz
                            </a>
                            <a href="/flashcards" class="btn btn-outline-primary">
                                <i class="fas fa-layer-group me-2"></i>Study Flashcards
                            </a>
                            <a href="/mock_exam" class="btn btn-outline-success">
                                <i class="fas fa-file-alt me-2"></i>Take Mock Exam
                            </a>
                            <a href="/ai_tutor" class="btn btn-outline-info">
                                <i class="fas fa-robot me-2"></i>Ask AI Tutor
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Domain Performance -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card-custom">
                    <div class="card-body">
                        <h5 class="card-title mb-4">
                            <i class="fas fa-chart-bar me-2"></i>Domain Performance
                        </h5>
                        <div class="row">
                            {domain_cards}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Study Recommendations -->
        <div class="row">
            <div class="col-md-8">
                <div class="card-custom">
                    <div class="card-body">
                        <h5 class="card-title">
                            <i class="fas fa-lightbulb me-2"></i>Personalized Recommendations
                        </h5>
                        <div class="alert alert-info alert-custom">
                            <h6><i class="fas fa-brain me-2"></i>Study Focus</h6>
                            <p class="mb-2">{progress['recommendation']}</p>
                            {f'<p class="mb-0"><strong>Weak Areas:</strong> {", ".join([domains[d]["name"] for d in progress["weak_domains"]])}</p>' if progress['weak_domains'] else ''}
                            {f'<p class="mb-0 mt-2"><strong>Strong Areas:</strong> {", ".join([domains[d]["name"] for d in progress["strong_domains"]])}</p>' if progress['strong_domains'] else ''}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card-custom">
                    <div class="card-body">
                        <h6 class="card-title">Study Tips</h6>
                        <ul class="list-unstyled small">
                            <li class="mb-2"><i class="fas fa-check text-success me-2"></i>Study consistently every day</li>
                            <li class="mb-2"><i class="fas fa-check text-success me-2"></i>Focus on weak domains first</li>
                            <li class="mb-2"><i class="fas fa-check text-success me-2"></i>Take breaks between sessions</li>
                            <li class="mb-2"><i class="fas fa-check text-success me-2"></i>Review flashcards regularly</li>
                            <li class="mb-0"><i class="fas fa-check text-success me-2"></i>Practice with mock exams</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return TemplateEngine._base_template({
            **context,
            'title': 'Dashboard - CPP Test Prep',
            'content': content
        })

"""
END OF SECTION 4: Template Engine and User Interface System
"""
def render_template(template_name: str, **context) -> str:
    """Render template with context variables"""
        template_map = {
            'base': TemplateEngine._base_template,
            'login': TemplateEngine._login_template,
            'register': TemplateEngine._register_template,
            'dashboard': TemplateEngine._dashboard_template,
            'quiz_setup': TemplateEngine._quiz_setup_template,
            'quiz_question': TemplateEngine._quiz_question_template,
            'quiz_results': TemplateEngine._quiz_results_template,
            'exam_setup': TemplateEngine._exam_setup_template,
            'exam_question': TemplateEngine._exam_question_template,
            'exam_results': TemplateEngine._exam_results_template,
            'flashcards': TemplateEngine._flashcards_template,
            'flashcard_study': TemplateEngine._flashcard_study_template,
            'ai_tutor': TemplateEngine._ai_tutor_template,
            'billing': TemplateEngine._billing_template,
            'profile': Template

"""
CPP Test Prep Platform - Complete Production Application
SECTION 5: Authentication and Core Routes
"""

# Authentication Routes
@app.route('/')
def index():
    """Home page - redirect based on authentication status"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(5, 300)  # 5 attempts per 5 minutes
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if not username or not password:
            flash('Please provide both username and password.', 'danger')
            return redirect(url_for('login'))
        
        # Find user
        users = data_manager.get_users()
        user = None
        for u in users.values():
            if u.username.lower() == username.lower() or u.email.lower() == username.lower():
                user = u
                break
        
        # Verify credentials
        if user and verify_password(password, user.password_hash):
            session['user_id'] = user.id
            session['login_time'] = time.time()
            
            # Update user login time
            user.last_login = dt.now().isoformat()
            data_manager.save_user(user)
            
            logger.info(f"User {user.username} logged in successfully")
            flash('Welcome back! You have been logged in successfully.', 'success')
            
            # Redirect to intended page or dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password. Please try again.', 'danger')
    
    return TemplateEngine.render_template('login', user=None)

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(3, 300)  # 3 attempts per 5 minutes
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        
        if not validate_email(email):
            errors.append('Please enter a valid email address.')
        
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        # Check for existing users
        users = data_manager.get_users()
        for user in users.values():
            if user.username.lower() == username.lower():
                errors.append('Username already exists. Please choose a different one.')
                break
            if user.email.lower() == email:
                errors.append('Email address already registered. Please use a different email.')
                break
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        user_id = str(uuid.uuid4())
        new_user = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=hash_password(password),
            created_at=dt.now().isoformat(),
            last_login=dt.now().isoformat()
        )
        
        data_manager.save_user(new_user)
        
        # Auto-login the new user
        session['user_id'] = user_id
        session['login_time'] = time.time()
        
        logger.info(f"New user registered: {username}")
        flash('Registration successful! Welcome to CPP Test Prep!', 'success')
        return redirect(url_for('billing'))  # New users need to choose subscription
    
    return TemplateEngine.render_template('register', user=None)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    user = get_current_user()
    if user:
        logger.info(f"User {user.username} logged out")
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with comprehensive metrics"""
    user = get_current_user()
    progress = ProgressAnalytics.calculate_overall_progress(user.id)
    
    # Get recent activity
    recent_quiz_attempts = data_manager.get_user_quiz_attempts(user.id)[:5]
    recent_exam_attempts = data_manager.get_user_exam_attempts(user.id)[:5]
    
    return TemplateEngine.render_template('dashboard', 
                                        user=user, 
                                        progress=progress, 
                                        domains=CPP_DOMAINS,
                                        recent_quiz_attempts=recent_quiz_attempts,
                                        recent_exam_attempts=recent_exam_attempts)

# Quiz System Routes
@app.route('/quiz')
@login_required
@subscription_required
def quiz():
    """Quiz setup page"""
    user = get_current_user()
    
    # Get question counts by domain for display
    domain_counts = {}
    for domain_id in CPP_DOMAINS.keys():
        domain_questions = data_manager.get_questions_by_domain(domain_id)
        domain_counts[domain_id] = len(domain_questions)
    
    return TemplateEngine.render_template('quiz_setup', 
                                        user=user,
                                        domains=CPP_DOMAINS,
                                        domain_counts=domain_counts)

@app.route('/start_quiz', methods=['POST'])
@login_required
@subscription_required
def start_quiz():
    """Start a new quiz session"""
    user = get_current_user()
    
    # Get form data
    question_count = int(request.form.get('question_count', 25))
    domain = request.form.get('domain', '').strip()
    question_types = request.form.getlist('question_types')
    difficulty_levels = request.form.getlist('difficulty_levels')
    timed_mode = bool(request.form.get('timed_mode'))
    
    # Validation
    if not question_types:
        flash('Please select at least one question type.', 'warning')
        return redirect(url_for('quiz'))
    
    if question_count < 5 or question_count > 200:
        flash('Question count must be between 5 and 200.', 'warning')
        return redirect(url_for('quiz'))
    
    # Convert difficulty levels to integers
    difficulty_ints = []
    for level in difficulty_levels:
        if level == '1':
            difficulty_ints.extend([1, 2])
        elif level == '3':
            difficulty_ints.append(3)
        elif level == '4':
            difficulty_ints.extend([4, 5])
    
    # Generate questions
    try:
        questions = generate_quiz_questions(
            domain=domain,
            question_types=question_types,
            difficulty_levels=difficulty_ints,
            count=question_count
        )
        
        if len(questions) < 5:
            flash('Not enough questions available with your selected criteria. Please adjust your filters.', 'warning')
            return redirect(url_for('quiz'))
        
        if len(questions) < question_count:
            flash(f'Only {len(questions)} questions available with your criteria.', 'info')
    
    except Exception as e:
        logger.error(f"Error generating quiz questions: {e}")
        flash('Error creating quiz. Please try again.', 'danger')
        return redirect(url_for('quiz'))
    
    # Store quiz session
    session['quiz_questions'] = [q.id for q in questions]
    session['quiz_answers'] = {}
    session['quiz_start_time'] = time.time()
    session['current_question'] = 0
    session['quiz_timed_mode'] = timed_mode
    session['quiz_marked_questions'] = set()
    session['quiz_type'] = 'practice'
    
    logger.info(f"User {user.username} started quiz with {len(questions)} questions")
    return redirect(url_for('take_quiz'))

@app.route('/take_quiz')
@login_required
@subscription_required
def take_quiz():
    """Take quiz - display current question"""
    if 'quiz_questions' not in session:
        flash('No active quiz session. Please start a new quiz.', 'warning')
        return redirect(url_for('quiz'))
    
    user = get_current_user()
    question_ids = session['quiz_questions']
    current_idx = session.get('current_question', 0)
    
    # Check if quiz is complete
    if current_idx >= len(question_ids):
        return redirect(url_for('quiz_results'))
    
    # Handle question navigation
    question_param = request.args.get('question')
    if question_param is not None:
        try:
            new_idx = int(question_param)
            if 0 <= new_idx < len(question_ids):
                session['current_question'] = new_idx
                current_idx = new_idx
        except (ValueError, TypeError):
            pass
    
    # Get current question
    questions = data_manager.get_questions()
    current_question = questions.get(question_ids[current_idx])
    
    if not current_question:
        flash('Question not found. Please start a new quiz.', 'danger')
        return redirect(url_for('quiz'))
    
    # Calculate time remaining
    start_time = session.get('quiz_start_time', time.time())
    elapsed = time.time() - start_time
    timed_mode = session.get('quiz_timed_mode', False)
    time_remaining = max(0, app.config['MAX_QUIZ_TIME'] - elapsed) if timed_mode else 0
    
    # Check if time has expired
    if timed_mode and time_remaining <= 0:
        flash('Time has expired! Quiz submitted automatically.', 'warning')
        return redirect(url_for('quiz_results'))
    
    current_answer = session['quiz_answers'].get(question_ids[current_idx], '')
    marked_questions = session.get('quiz_marked_questions', set())
    
    return TemplateEngine.render_template('quiz_question',
                                        user=user,
                                        current_question=current_question,
                                        current_idx=current_idx,
                                        total_questions=len(question_ids),
                                        question_ids=question_ids,
                                        answers=session['quiz_answers'],
                                        marked_questions=marked_questions,
                                        current_answer=current_answer,
                                        time_remaining=int(time_remaining),
                                        timed_mode=timed_mode)

@app.route('/submit_quiz_answer', methods=['POST'])
@login_required
@subscription_required
def submit_quiz_answer():
    """Submit answer for current quiz question"""
    if 'quiz_questions' not in session:
        return redirect(url_for('quiz'))
    
    answer = request.form.get('answer', '').strip()
    action = request.form.get('action', 'save')
    
    current_idx = session.get('current_question', 0)
    question_ids = session['quiz_questions']
    
    # Save answer if provided
    if answer:
        session['quiz_answers'][question_ids[current_idx]] = answer
        session.modified = True
    
    # Handle different actions
    if action == 'next' and current_idx < len(question_ids) - 1:
        session['current_question'] = current_idx + 1
        return redirect(url_for('take_quiz'))
    elif action == 'previous' and current_idx > 0:
        session['current_question'] = current_idx - 1
        return redirect(url_for('take_quiz'))
    elif action == 'finish':
        return redirect(url_for('quiz_results'))
    elif action == 'save':
        # Just save and stay on current question
        return redirect(url_for('take_quiz'))
    
    return redirect(url_for('take_quiz'))

@app.route('/toggle_quiz_mark', methods=['POST'])
@login_required
@subscription_required
def toggle_quiz_mark():
    """Toggle question mark for review"""
    if 'quiz_marked_questions' not in session:
        session['quiz_marked_questions'] = set()
    
    data = request.get_json()
    question_id = data.get('question_id')
    
    if not question_id:
        return jsonify({'error': 'Question ID required'}), 400
    
    marked = session['quiz_marked_questions']
    if question_id in marked:
        marked.remove(question_id)
        status = 'unmarked'
    else:
        marked.add(question_id)
        status = 'marked'
    
    session['quiz_marked_questions'] = marked
    session.modified = True
    
    return jsonify({'status': status})

@app.route('/quiz_results')
@login_required
@subscription_required
def quiz_results():
    """Display quiz results with detailed analysis"""
    if 'quiz_questions' not in session:
        flash('No quiz session found.', 'warning')
        return redirect(url_for('quiz'))
    
    user = get_current_user()
    
    # Get quiz data
    questions = data_manager.get_questions()
    question_ids = session['quiz_questions']
    answers = session['quiz_answers']
    start_time = session.get('quiz_start_time', time.time())
    quiz_type = session.get('quiz_type', 'practice')
    
    # Calculate results
    correct_count = 0
    total_questions = len(question_ids)
    question_results = []
    
    for qid in question_ids:
        question = questions.get(qid)
        if not question:
            continue
            
        user_answer = answers.get(qid, '')
        is_correct = user_answer == question.correct_answer
        
        if is_correct:
            correct_count += 1
        
        question_results.append({
            'question': question,
            'user_answer': user_answer,
            'correct': is_correct,
            'answered': bool(user_answer)
        })
    
    # Calculate scores
    overall_score = correct_count / total_questions if total_questions > 0 else 0
    domain_scores = calculate_domain_scores([questions[qid] for qid in question_ids], answers)
    time_taken = int(time.time() - start_time)
    
    # Save quiz attempt
    attempt = QuizAttempt(
        id=str(uuid.uuid4()),
        user_id=user.id,
        questions=question_ids,
        answers=answers,
        score=overall_score,
        domain_scores=domain_scores,
        completed_at=dt.now().isoformat(),
        time_taken=time_taken,
        quiz_type=quiz_type,
        question_count=total_questions,
        timed_mode=session.get('quiz_timed_mode', False)
    )
    
    data_manager.save_quiz_attempt(attempt)
    
    # Update user stats
    user.quiz_attempts += 1
    user.total_study_time += time_taken
    data_manager.save_user(user)
    
    # Update activity tracking
    update_user_activity(user.id, 'quiz', time_taken)
    
    # Clear quiz session
    quiz_keys = ['quiz_questions', 'quiz_answers', 'quiz_start_time', 'current_question', 
                 'quiz_timed_mode', 'quiz_marked_questions', 'quiz_type']
    for key in quiz_keys:
        session.pop(key, None)
    
    logger.info(f"User {user.username} completed quiz: {correct_count}/{total_questions} ({overall_score:.1%})")
    
    return TemplateEngine.render_template('quiz_results',
                                        user=user,
                                        attempt=attempt,
                                        question_results=question_results,
                                        domains=CPP_DOMAINS)

# Auto-save functionality
@app.route('/auto_save', methods=['POST'])
@login_required
def auto_save():
    """Auto-save quiz progress"""
    if 'quiz_questions' not in session:
        return jsonify({'status': 'no_session'}), 400
    
    # This could be enhanced to save progress to database
    # For now, we rely on session storage
    return jsonify({'status': 'saved'})

"""
END OF SECTION 5: Authentication and Core Routes
"""
"""
CPP Test Prep Platform - Complete Production Application
SECTION 6: Quiz and Exam Templates (Missing from Section 4)
"""

# Additional Template Methods for TemplateEngine class
class TemplateEngineExtensions:
    """Extensions to the main TemplateEngine class"""
    
    @staticmethod
    def _quiz_setup_template(context: dict) -> str:
        """Quiz setup page template"""
        domains = context['domains']
        domain_counts = context.get('domain_counts', {})
        
        # Build domain options
        domain_options = ""
        for domain_id, domain_info in domains.items():
            count = domain_counts.get(domain_id, 0)
            domain_options += f'''
            <option value="{domain_id}">{domain_info["name"]} ({count} questions)</option>
            '''
        
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-10">
                <div class="card-custom">
                    <div class="card-body">
                        <div class="text-center mb-4">
                            <i class="fas fa-question-circle text-primary" style="font-size: 3rem;"></i>
                            <h2 class="mt-3 mb-1">Practice Quiz Setup</h2>
                            <p class="text-muted">Customize your practice session</p>
                        </div>
                        
                        <form action="/start_quiz" method="POST" novalidate>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-4">
                                        <label for="question_count" class="form-label fw-semibold">
                                            <i class="fas fa-list-ol me-2"></i>Number of Questions
                                        </label>
                                        <select class="form-control" id="question_count" name="question_count" required>
                                            <option value="10">10 Questions (Quick Review - 10 min)</option>
                                            <option value="25" selected>25 Questions (Standard - 25 min)</option>
                                            <option value="50">50 Questions (Extended - 50 min)</option>
                                            <option value="100">100 Questions (Comprehensive - 1.5 hrs)</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <div class="mb-4">
                                        <label for="domain" class="form-label fw-semibold">
                                            <i class="fas fa-bullseye me-2"></i>Focus Domain
                                        </label>
                                        <select class="form-control" id="domain" name="domain">
                                            <option value="">All Domains (Mixed Practice)</option>
                                            {domain_options}
                                        </select>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label class="form-label fw-semibold">
                                    <i class="fas fa-clipboard-question me-2"></i>Question Types
                                </label>
                                <div class="row">
                                    <div class="col-md-4">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="multiple_choice" 
                                                   name="question_types" value="multiple_choice" checked>
                                            <label class="form-check-label" for="multiple_choice">
                                                <i class="fas fa-list-ul me-2"></i>Multiple Choice
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="true_false" 
                                                   name="question_types" value="true_false" checked>
                                            <label class="form-check-label" for="true_false">
                                                <i class="fas fa-check-circle me-2"></i>True/False
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="scenario" 
                                                   name="question_types" value="scenario" checked>
                                            <label class="form-check-label" for="scenario">
                                                <i class="fas fa-users me-2"></i>Scenario Based
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label class="form-label fw-semibold">
                                    <i class="fas fa-signal me-2"></i>Difficulty Level
                                </label>
                                <div class="row">
                                    <div class="col-md-3">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="difficulty_1" 
                                                   name="difficulty_levels" value="1" checked>
                                            <label class="form-check-label" for="difficulty_1">
                                                <span class="badge bg-success me-2">Basic</span>(1-2)
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="difficulty_3" 
                                                   name="difficulty_levels" value="3" checked>
                                            <label class="form-check-label" for="difficulty_3">
                                                <span class="badge bg-warning me-2">Intermediate</span>(3)
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="difficulty_4" 
                                                   name="difficulty_levels" value="4" checked>
                                            <label class="form-check-label" for="difficulty_4">
                                                <span class="badge bg-danger me-2">Advanced</span>(4-5)
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="form-check form-check-custom">
                                            <input class="form-check-input" type="checkbox" id="timed_mode" 
                                                   name="timed_mode" value="1">
                                            <label class="form-check-label" for="timed_mode">
                                                <i class="fas fa-clock me-2 text-warning"></i>Timed Mode
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="text-center">
                                <button type="submit" class="btn-custom btn-lg px-5">
                                    <i class="fas fa-play me-2"></i>Start Practice Quiz
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Ensure at least one question type is selected
            document.querySelector('form').addEventListener('submit', function(e) {{
                const questionTypes = document.querySelectorAll('input[name="question_types"]:checked');
                const difficultyLevels = document.querySelectorAll('input[name="difficulty_levels"]:checked');
                
                if (questionTypes.length === 0) {{
                    e.preventDefault();
                    showFlashMessage('Please select at least one question type.', 'warning');
                    return;
                }}
                
                if (difficultyLevels.length === 0) {{
                    e.preventDefault();
                    showFlashMessage('Please select at least one difficulty level.', 'warning');
                    return;
                }}
            }});
        </script>
        '''
        
        return TemplateEngine._base_template({
            **context,
            'title': 'Practice Quiz Setup - CPP Test Prep',
            'content': content
        })
    
    @staticmethod
    def _quiz_question_template(context: dict) -> str:
        """Quiz question template with navigation - SYNTAX FIXED"""
        current_question = context['current_question']
        current_idx = context['current_idx']
        total_questions = context['total_questions']
        question_ids = context['question_ids']
        answers = context['answers']
        marked_questions = context.get('marked_questions', set())
        current_answer = context['current_answer']
        time_remaining = context['time_remaining']
        timed_mode = context.get('timed_mode', False)
        
        # Generate option HTML safely
        options_html = ""
        for i, option in enumerate(current_question.options):
            checked = 'checked' if current_answer == option else ''
            option_id = f"option_{i}"
            options_html += f'''
            <div class="form-check mb-3">
                <input class="form-check-input" type="radio" name="answer" 
                       id="{option_id}" value="{option}" {checked}>
                <label class="form-check-label" for="{option_id}">
                    <strong>{chr(65 + i)}.</strong> {option}
                </label>
            </div>
            '''
        
        # Generate question navigation
        nav_html = ""
        for i in range(total_questions):
            classes = ["question-nav-btn"]
            if i == current_idx:
                classes.append("current")
            elif question_ids[i] in answers:
                classes.append("answered")
            if question_ids[i] in marked_questions:
                classes.append("marked")
            
            nav_html += f'<div class="{" ".join(classes)}" onclick="goToQuestion({i})" title="Question {i + 1}">{i + 1}</div>'
        
        # Navigation buttons
        prev_btn = ""
        if current_idx > 0:
            prev_btn = '''
            <button type="submit" name="action" value="previous" class="btn btn-outline-secondary">
                <i class="fas fa-arrow-left me-2"></i>Previous
            </button>
            '''
        
        next_btn = ""
        if current_idx < total_questions - 1:
            next_btn = '''
            <button type="submit" name="action" value="next" class="btn-custom">
                Next <i class="fas fa-arrow-right ms-2"></i>
            </button>
            '''
        else:
            next_btn = '''
            <button type="submit" name="action" value="finish" class="btn btn-success">
                <i class="fas fa-check me-2"></i>Finish Quiz
            </button>
            '''
        
        is_marked = current_question.id in marked_questions
        mark_text = "Unmark" if is_marked else "Mark for Review"
        mark_class = "btn-warning" if is_marked else "btn-outline-warning"
        
        # Timer HTML
        timer_html = ""
        if timed_mode and time_remaining > 0:
            timer_html = f'''
            <div class="timer-display" id="timer">
                <i class="fas fa-clock me-2"></i>
                Time Remaining: <span id="timeDisplay">{time_remaining}</span>
            </div>
            '''
        
        answered_count = len([qid for qid in question_ids if qid in answers])
        marked_count = len(marked_questions)
        
        content = f'''
        {timer_html}
        
        <div class="row">
            <div class="col-lg-9">
                <div class="card-custom">
                    <div class="card-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">Question {current_idx + 1} of {total_questions}</h5>
                            <div>
                                <span class="badge bg-primary me-2">{CPP_DOMAINS[current_question.domain]['name']}</span>
                                <span class="badge bg-secondary me-2">Difficulty: {current_question.difficulty}/5</span>
                                <button type="button" class="btn btn-sm {mark_class}" onclick="toggleMark()">
                                    <i class="fas fa-flag"></i> {mark_text}
                                </button>
                            </div>
                        </div>
                        
                        <div class="progress mt-3" style="height: 8px;">
                            <div class="progress-bar" role="progressbar" 
                                 style="width: {((current_idx + 1) / total_questions) * 100:.1f}%"></div>
                        </div>
                    </div>
                    
                    <div class="card-body">
                        <form method="POST" action="/submit_quiz_answer" id="questionForm">
                            <div class="mb-4">
                                <h6 class="question-text">{current_question.question}</h6>
                            </div>
                            
                            <div class="mb-4">
                                {options_html}
                            </div>
                            
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    {prev_btn}
                                </div>
                                <div>
                                    <button type="submit" name="action" value="save" class="btn btn-outline-primary me-2">
                                        <i class="fas fa-save me-1"></i>Save
                                    </button>
                                    {next_btn}
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3">
                <div class="card-custom">
                    <div class="card-header">
                        <h6 class="mb-0">
                            <i class="fas fa-map me-2"></i>Question Navigation
                        </h6>
                    </div>
                    <div class="card-body">
                        <div class="question-nav">
                            {nav_html}
                        </div>
                        
                        <div class="mt-3 mb-3">
                            <div class="d-flex justify-content-between text-sm">
                                <span><i class="fas fa-circle text-success me-1"></i>Answered: {answered_count}</span>
                                <span><i class="fas fa-circle text-warning me-1"></i>Marked: {marked_count}</span>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="button" class="btn btn-success" onclick="confirmSubmit()">
                                <i class="fas fa-paper-plane me-2"></i>Submit Quiz
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="card-custom mt-3">
                    <div class="card-body">
                        <h6 class="card-title">Quick Stats</h6>
                        <div class="small">
                            <div class="d-flex justify-content-between mb-1">
                                <span>Progress:</span>
                                <span>{current_idx + 1}/{total_questions}</span>
                            </div>
                            <div class="d-flex justify-content-between mb-1">
                                <span>Answered:</span>
                                <span>{answered_count}/{total_questions}</span>
                            </div>
                            <div class="d-flex justify-content-between">
                                <span>Remaining:</span>
                                <span>{total_questions - current_idx - 1}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Submit Confirmation Modal -->
        <div class="modal fade" id="submitModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-paper-plane me-2"></i>Submit Quiz
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-info">
                            <h6>Quiz Summary</h6>
                            <div class="row">
                                <div class="col-6">
                                    <strong>Total Questions:</strong> {total_questions}<br>
                                    <strong>Answered:</strong> <span id="modalAnsweredCount">{answered_count}</span>
                                </div>
                                <div class="col-6">
                                    <strong>Marked for Review:</strong> <span id="modalMarkedCount">{marked_count}</span><br>
                                    <strong>Unanswered:</strong> <span id="modalUnansweredCount">{total_questions - answered_count}</span>
                                </div>
                            </div>
                        </div>
                        <p>Are you sure you want to submit your quiz? You cannot change your answers after submission.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            <i class="fas fa-edit me-2"></i>Continue Editing
                        </button>
                        <form method="POST" action="/submit_quiz_answer" style="display: inline;">
                            <button type="submit" name="action" value="finish" class="btn btn-success">
                                <i class="fas fa-check me-2"></i>Submit Final Quiz
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        # Build JavaScript - avoiding nested f-strings by building timer code separately
        timer_script = ""
        if timed_mode and time_remaining > 0:
            # Build timer initialization separately to avoid nested f-strings
            timer_init = f"let timeRemaining = {time_remaining};"
            timer_script = timer_init + '''
            
            function updateTimer() {
                if (timeRemaining <= 0) {
                    showFlashMessage('Time expired! Submitting quiz automatically.', 'warning');
                    setTimeout(() => {
                        document.getElementById('questionForm').submit();
                    }, 2000);
                    return;
                }
                
                const hours = Math.floor(timeRemaining / 3600);
                const minutes = Math.floor((timeRemaining % 3600) / 60);
                const seconds = timeRemaining % 60;
                
                let display = '';
                if (hours > 0) {
                    display = hours + ':' + minutes.toString().padStart(2, '0') + ':' + seconds.toString().padStart(2, '0');
                } else {
                    display = minutes + ':' + seconds.toString().padStart(2, '0');
                }
                
                document.getElementById('timeDisplay').textContent = display;
                timeRemaining--;
            }
            
            setInterval(updateTimer, 1000);
            updateTimer();
            '''
        
        # Build complete script section
        question_id_escaped = current_question.id.replace("'", "\\'")
        scripts = f'''
        <script>
            {timer_script}
            
            function goToQuestion(index) {{
                window.location.href = '/take_quiz?question=' + index;
            }}
            
            function toggleMark() {{
                fetch('/toggle_quiz_mark', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{question_id: '{question_id_escaped}'}})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.status === 'marked') {{
                        showFlashMessage('Question marked for review', 'info');
                    }} else {{
                        showFlashMessage('Question unmarked', 'info');
                    }}
                    setTimeout(() => location.reload(), 1000);
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    showFlashMessage('Error updating mark status', 'danger');
                }});
            }}
            
            function confirmSubmit() {{
                const answeredCount = document.querySelectorAll('.question-nav-btn.answered').length;
                const markedCount = document.querySelectorAll('.question-nav-btn.marked').length;
                const unansweredCount = {total_questions} - answeredCount;
                
                document.getElementById('modalAnsweredCount').textContent = answeredCount;
                document.getElementById('modalMarkedCount').textContent = markedCount;
                document.getElementById('modalUnansweredCount').textContent = unansweredCount;
                
                new bootstrap.Modal(document.getElementById('submitModal')).show();
            }}
            
            // Auto-save functionality
            let autoSaveTimeout;
            document.querySelectorAll('input[name="answer"]').forEach(input => {{
                input.addEventListener('change', function() {{
                    clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = setTimeout(() => {{
                        const formData = new FormData();
                        formData.append('answer', this.value);
                        formData.append('action', 'save');
                        
                        fetch('/submit_quiz_answer', {{
                            method: 'POST',
                            body: formData
                        }}).then(() => {{
                            // Update navigation to show answered
                            const currentBtn = document.querySelector('.question-nav-btn.current');
                            if (currentBtn && !currentBtn.classList.contains('answered')) {{
                                currentBtn.classList.add('answered');
                            }}
                        }}).catch(error => console.log('Auto-save failed:', error));
                    }}, 1000);
                }});
            }});
            
            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {{
                if (e.ctrlKey) {{
                    switch(e.key) {{
                        case 'ArrowLeft':
                            e.preventDefault();
                            const prevBtn = document.querySelector('button[name="action"][value="previous"]');
                            if (prevBtn) prevBtn.click();
                            break;
                        case 'ArrowRight':
                            e.preventDefault();
                            const nextBtn = document.querySelector('button[name="action"][value="next"]');
                            if (nextBtn) nextBtn.click();
                            break;
                        case 'Enter':
                            e.preventDefault();
                            confirmSubmit();
                            break;
                        case 'm':
                            e.preventDefault();
                            toggleMark();
                            break;
                    }}
                }}
            }});
        </script>
        '''
        
        return TemplateEngine._base_template({
            **context,
            'title': f'Quiz Question {current_idx + 1} - CPP Test Prep',
            'content': content,
            'scripts': scripts
        })
    
    @staticmethod
    def _quiz_results_template(context: dict) -> str:
        """Quiz results template with detailed analysis"""
        attempt = context['attempt']
        question_results = context['question_results']
        domains = context['domains']
        
        # Calculate performance metrics
        score_percent = int(attempt.score * 100)
        score_class = "success" if attempt.score >= 0.8 else "warning" if attempt.score >= 0.6 else "danger"
        
        correct_count = sum(1 for result in question_results if result['correct'])
        answered_count = sum(1 for result in question_results if result['answered'])
        
        # Build domain breakdown
        domain_breakdown = ""
        for domain_id, domain_info in domains.items():
            if domain_id in attempt.domain_scores:
                domain_score = attempt.domain_scores[domain_id]
                domain_percent = int(domain_score * 100)
                domain_questions = [r for r in question_results if r['question'].domain == domain_id]
                
                if domain_questions:
                    performance_class = "success" if domain_score >= 0.8 else "warning" if domain_score >= 0.6 else "danger"
                    performance_text = "Excellent" if domain_score >= 0.8 else "Good" if domain_score >= 0.6 else "Needs Work"
                    
                    domain_breakdown += f'''
                    <tr>
                        <td>
                            <strong>{domain_info['name']}</strong>
                            <br><small class="text-muted">{domain_info['description'][:50]}...</small>
                        </td>
                        <td class="text-center">{len([r for r in domain_questions if r['correct']])}/{len(domain_questions)}</td>
                        <td class="text-center">{domain_percent}%</td>
                        <td class="text-center">
                            <span class="badge bg-{performance_class}">{performance_text}</span>
                        </td>
                    </tr>
                    '''
        
        # Generate recommendations
        weak_domains = [domain_id for domain_id, score in attempt.domain_scores.items() if score < 0.6]
        strong_domains = [domain_id for domain_id, score in attempt.domain_scores.items() if score >= 0.8]
        
        recommendations = []
        if attempt.score < 0.5:
            recommendations.extend([
                "Focus on fundamental concepts across all CPP domains",
                "Start with flashcard study to build your knowledge base",
                "Review the CPP study guide and official materials"
            ])
        elif attempt.score < 0.7:
            recommendations.append("You're making solid progress - continue practicing regularly")
            if weak_domains:
                domain_names = [domains[d]['name'] for d in weak_domains[:2]]
                recommendations.append(f"Focus extra attention on: {', '.join(domain_names)}")
        else:
            recommendations.extend([
                "Excellent work! You're performing at a high level",
                "Consider taking full-length mock exams to build test endurance",
                "Continue regular practice to maintain your knowledge"
            ])
        
        recommendations_html = "".join(f"<li>{rec}</li>" for rec in recommendations)
        
        # Time analysis
        time_per_question = attempt.time_taken / attempt.question_count if attempt.question_count > 0 else 0
        time_analysis = ""
        if attempt.timed_mode:
            if time_per_question < 60:
                time_analysis = f"Fast pace ({time_per_question:.1f}s per question) - good time management!"
            elif time_per_question > 180:
                time_analysis = f"Slow pace ({time_per_question/60:.1f}min per question) - consider practicing under time pressure"
            else:
                time_analysis = f"Good pace ({time_per_question:.1f}s per question)"
        
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-12">
                <div class="card-custom">
                    <div class="card-header text-center">
                        <h3 class="mb-1">
                            <i class="fas fa-chart-line me-2"></i>Quiz Results
                        </h3>
                        <p class="text-muted mb-0">Detailed Performance Analysis</p>
                    </div>
                    
                    <div class="card-body">
                        <!-- Overall Score Banner -->
                        <div class="alert alert-{score_class} alert-custom text-center mb-4">
                            <div class="row align-items-center">
                                <div class="col-md-3">
                                    <i class="fas fa-trophy fa-3x"></i>
                                </div>
                                <div class="col-md-6">
                                    <h2 class="mb-1">Final Score: {score_percent}%</h2>
                                    <p class="mb-0">{correct_count} correct out of {attempt.question_count} questions</p>
                                    {f'<p class="mb-0"><small>{time_analysis}</small></p>' if time_analysis else ''}
                                </div>
                                <div class="col-md-3">
                                    <div class="progress-circle">
                                        <svg width="120" height="120" viewBox="0 0 120 120">
                                            <circle cx="60" cy="60" r="50" fill="none" stroke="#e2e8f0" stroke-width="8"/>
                                            <circle cx="60" cy="60" r="50" fill="none" stroke="currentColor" stroke-width="8"
                                                    stroke-dasharray="{score_percent * 3.14} 314"
                                                    stroke-linecap="round" transform="rotate(-90 60 60)"/>
                                        </svg>
                                        <div class="progress-text" style="font-size: 1.5rem;">{score_percent}%</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Quick Stats -->
                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <div class="stat-icon text-success">
                                        <i class="fas fa-check-circle"></i>
                                    </div>
                                    <div class="stat-number text-success">{correct_count}</div>
                                    <div class="stat-label">Correct</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <div class="stat-icon text-danger">
                                        <i class="fas fa-times-circle"></i>
                                    </div>
                                    <div class="stat-number text-danger">{attempt.question_count - correct_count}</div>
                                    <div class="stat-label">Incorrect</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <div class="stat-icon text-primary">
                                        <i class="fas fa-clock"></i>
                                    </div>
                                    <div class="stat-number text-primary">{attempt.time_taken // 60:.0f}m</div>
                                    <div class="stat-label">Time Taken</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <div class="stat-icon text-info">
                                        <i class="fas fa-percentage"></i>
                                    </div>
                                    <div class="stat-number text-info">{(answered_count/attempt.question_count)*100:.0f}%</div>
                                    <div class="stat-label">Completion</div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Domain Performance -->
                        <div class="row mb-4">
                            <div class="col-12">
                                <h5 class="mb-3">
                                    <i class="fas fa-chart-bar me-2"></i>Performance by Domain
                                </h5>
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Domain</th>
                                                <th class="text-center">Correct/Total</th>
                                                <th class="text-center">Score</th>
                                                <th class="text-center">Performance</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {domain_breakdown}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Recommendations -->
                        <div class="row mb-4">
                            <div class="col-md-8">
                                <div class="card border-info">
                                    <div class="card-header bg-info text-white">
                                        <h6 class="mb-0">
                                            <i class="fas fa-lightbulb me-2"></i>Study Recommendations
                                        </h6>
                                    </div>
                                    <div class="card-body">
                                        <ul class="mb-0">
                                            {recommendations_html}
                                        </ul>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card border-secondary">
                                    <div class="card-header bg-secondary text-white">
                                        <h6 class="mb-0">
                                            <i class="fas fa-info-circle me-2"></i>Next Steps
                                        </h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="d-grid gap-2">
                                            <a href="/quiz" class="btn btn-primary btn-sm">
                                                <i class="fas fa-redo me-2"></i>Take Another Quiz
                                            </a>
                                            <a href="/flashcards" class="btn btn-outline-primary btn-sm">
                                                <i class="fas fa-layer-group me-2"></i>Study Flashcards
                                            </a>
                                            <a href="/mock_exam" class="btn btn-outline-success btn-sm">
                                                <i class="fas fa-file-alt me-2"></i>Mock Exam
                                            </a>
                                            <a href="/ai_tutor" class="btn btn-outline-info btn-sm">
                                                <i class="fas fa-robot me-2"></i>Ask AI Tutor
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Action Buttons -->
                        <div class="text-center">
                            <a href="/dashboard" class="btn btn-outline-secondary me-2">
                                <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                            </a>
                            <button class="btn btn-outline-primary" onclick="window.print()">
                                <i class="fas fa-print me-2"></i>Print Results
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return TemplateEngine._base_template({
            **context,
            'title': 'Quiz Results - CPP Test Prep',
            'content': content
        })

# Bind extension methods to main TemplateEngine class
TemplateEngine._quiz_setup_template = TemplateEngineExtensions._quiz_setup_template
TemplateEngine._quiz_question_template = TemplateEngineExtensions._quiz_question_template  
TemplateEngine._quiz_results_template = TemplateEngineExtensions._quiz_results_template

"""
END OF SECTION 6: Quiz and Exam Templates
"""

