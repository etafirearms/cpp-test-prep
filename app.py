#!/usr/bin/env python3
"""
CPP Test Prep Platform - Complete Production Application
Section 1: Core Setup, Configuration, Imports, Security, Data Management
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
    
    def get_users(self) -> Dict[str, User]:
        """Get all users"""
        data = self._load_data('users.json')
        return {k: User(**v) for k, v in data.items()}
    
    def save_user(self, user: User):
        """Save user"""
        users = self._load_data('users.json')
        users[user.id] = asdict(user)
        self._save_data('users.json', users)
    
    def get_questions(self) -> Dict[str, Question]:
        """Get all questions"""
        data = self._load_data('questions.json')
        return {k: Question(**v) for k, v in data.items()}
    
    def get_flashcards(self) -> Dict[str, Flashcard]:
        """Get all flashcards"""
        data = self._load_data('flashcards.json')
        return {k: Flashcard(**v) for k, v in data.items()}
    
    def save_flashcard(self, flashcard: Flashcard):
        """Save flashcard"""
        flashcards = self._load_data('flashcards.json')
        flashcards[flashcard.id] = asdict(flashcard)
        self._save_data('flashcards.json', flashcards)
    
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

# Initialize Data Manager
data_manager = DataManager(app.config['DATA_DIR'])

# CPP Domain Configuration
CPP_DOMAINS = {
    'D1': {'name': 'Physical Security', 'weight': 0.22},
    'D2': {'name': 'Personnel Security', 'weight': 0.15},
    'D3': {'name': 'Information Systems Security', 'weight': 0.09},
    'D4': {'name': 'Crisis Management', 'weight': 0.11},
    'D5': {'name': 'Investigations', 'weight': 0.16},
    'D6': {'name': 'Legal and Regulatory', 'weight': 0.14},
    'D7': {'name': 'Professional and Ethical Responsibilities', 'weight': 0.13}
}

# Content Generation Engine
class ContentEngine:
    """Manages question and flashcard content generation"""
    
    @staticmethod
    def _get_default_questions() -> Dict[str, dict]:
        """Generate comprehensive question bank with 500 questions"""
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
        
        # Type distribution: 250 MC, 125 T/F, 125 Scenarios
        for domain, count in domain_counts.items():
            mc_count = int(count * 0.5)
            tf_count = int(count * 0.25)
            scenario_count = count - mc_count - tf_count
            
            # Multiple Choice Questions
            for i in range(mc_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'multiple_choice',
                    'question': ContentEngine._generate_mc_question(domain, i),
                    'options': ContentEngine._generate_mc_options(domain, i),
                    'correct_answer': 'A',
                    'explanation': ContentEngine._generate_explanation(domain, i, 'mc'),
                    'difficulty': random.randint(1, 5)
                }
                question_id += 1
            
            # True/False Questions
            for i in range(tf_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'true_false',
                    'question': ContentEngine._generate_tf_question(domain, i),
                    'options': ['True', 'False'],
                    'correct_answer': 'True' if i % 2 == 0 else 'False',
                    'explanation': ContentEngine._generate_explanation(domain, i, 'tf'),
                    'difficulty': random.randint(1, 5)
                }
                question_id += 1
            
            # Scenario Questions
            for i in range(scenario_count):
                questions[str(question_id)] = {
                    'id': str(question_id),
                    'domain': domain,
                    'type': 'scenario',
                    'question': ContentEngine._generate_scenario_question(domain, i),
                    'options': ContentEngine._generate_scenario_options(domain, i),
                    'correct_answer': 'A',
                    'explanation': ContentEngine._generate_explanation(domain, i, 'scenario'),
                    'difficulty': random.randint(3, 5)
                }
                question_id += 1
        
        return questions
    
    @staticmethod
    def _generate_mc_question(domain: str, index: int) -> str:
        """Generate multiple choice questions by domain"""
        templates = {
            'D1': [
                "What is the most effective method for controlling access to a secured facility?",
                "Which type of barrier provides the best perimeter security for high-value assets?",
                "What is the recommended minimum illumination level for parking areas?",
                "Which access control method provides the highest level of security?",
                "What is the primary purpose of a mantrap entry system?"
            ],
            'D2': [
                "What is the most critical component of a personnel security program?",
                "Which background investigation type is required for top secret clearance?",
                "What is the primary purpose of security awareness training?",
                "Which method is most effective for detecting insider threats?",
                "What is the recommended frequency for security clearance renewals?"
            ],
            'D3': [
                "What is the most effective method for securing database systems?",
                "Which encryption standard is recommended for protecting sensitive data?",
                "What is the primary purpose of network segmentation?",
                "Which authentication method provides the strongest security?",
                "What is the recommended frequency for security patch updates?"
            ],
            'D4': [
                "What is the first priority during a security incident?",
                "Which communication method is most reliable during emergencies?",
                "What is the primary purpose of a business continuity plan?",
                "Which factor is most critical in crisis decision-making?",
                "What is the recommended structure for an incident response team?"
            ],
            'D5': [
                "What is the most important principle of evidence collection?",
                "Which interview technique is most effective for gathering information?",
                "What is the primary purpose of surveillance operations?",
                "Which documentation standard is required for legal proceedings?",
                "What is the recommended approach for conducting background investigations?"
            ],
            'D6': [
                "What is the primary purpose of security policies and procedures?",
                "Which legal concept is most relevant to security operations?",
                "What is the recommended approach for handling legal compliance?",
                "Which documentation is required for regulatory audits?",
                "What is the most important consideration in contract security?"
            ],
            'D7': [
                "What is the most important ethical principle in security practice?",
                "Which professional standard guides security practitioner conduct?",
                "What is the primary purpose of continuing education requirements?",
                "Which ethical consideration is paramount in investigations?",
                "What is the recommended approach for handling conflicts of interest?"
            ]
        }
        return templates.get(domain, ["Generic security question"])[index % len(templates.get(domain, ["Generic"]))]
    
    @staticmethod
    def _generate_mc_options(domain: str, index: int) -> List[str]:
        """Generate multiple choice options"""
        option_sets = [
            ["Card readers with biometric verification", "Key-based locks", "Security guards only", "Video surveillance"],
            ["Multi-layered approach with redundancy", "Single point of control", "Automated systems only", "Manual verification"],
            ["Technology-based solutions", "Human resources", "Physical barriers", "Integrated approach"],
            ["Immediate response", "Documentation", "Investigation", "Prevention"]
        ]
        return option_sets[index % len(option_sets)]
    
    @staticmethod
    def _generate_tf_question(domain: str, index: int) -> str:
        """Generate true/false questions"""
        templates = {
            'D1': [
                "Perimeter security should always include multiple layers of protection.",
                "Video surveillance can completely replace the need for security guards.",
                "Access control systems should log all entry and exit attempts.",
                "Physical barriers are more important than electronic security measures."
            ],
            'D2': [
                "Background investigations are required for all employees with security access.",
                "Security clearances never expire once granted.",
                "Insider threats pose a greater risk than external threats.",
                "Security awareness training should be conducted annually."
            ],
            'D3': [
                "Encryption is necessary for all data transmission.",
                "Network firewalls provide complete protection against cyber attacks.",
                "Multi-factor authentication significantly improves security.",
                "Security patches should be applied immediately upon release."
            ],
            'D4': [
                "Life safety is always the top priority in crisis situations.",
                "Crisis management plans should be tested regularly.",
                "Communication systems should have backup capabilities.",
                "Decision-making authority should be centralized during crises."
            ],
            'D5': [
                "Evidence chain of custody must be maintained at all times.",
                "Surveillance operations require legal authorization.",
                "Witness interviews should be recorded whenever possible.",
                "Investigation reports must be objective and factual."
            ],
            'D6': [
                "Security policies must comply with applicable laws and regulations.",
                "Legal counsel should be involved in security policy development.",
                "Regulatory compliance is optional for private organizations.",
                "Contract security services must meet the same standards as in-house security."
            ],
            'D7': [
                "Professional ethics override organizational policies.",
                "Continuing education is essential for security professionals.",
                "Conflicts of interest must be disclosed and managed.",
                "Professional certification demonstrates competency."
            ]
        }
        return templates.get(domain, ["Generic true/false question"])[index % len(templates.get(domain, ["Generic"]))]
    
    @staticmethod
    def _generate_scenario_question(domain: str, index: int) -> str:
        """Generate scenario-based questions"""
        scenarios = {
            'D1': [
                "A company is experiencing repeated security breaches at their main entrance. Employees are allowing unauthorized visitors to enter by holding doors open. What is the most effective solution?",
                "During a security assessment, you discover that the parking garage has poor lighting and multiple blind spots. What should be your primary recommendation?"
            ],
            'D2': [
                "An employee with security clearance is showing signs of financial distress and has been asking colleagues about classified projects outside their area. What action should be taken?",
                "A new contractor needs access to sensitive areas but their background investigation is still pending. How should this situation be handled?"
            ],
            'D3': [
                "Your organization's network has been compromised and sensitive data may have been accessed. What is your immediate priority?",
                "Employees are reporting suspicious emails that appear to be phishing attempts. What is the most appropriate response?"
            ],
            'D4': [
                "During a fire evacuation, some employees are refusing to leave their workstations to save important files. How should security personnel respond?",
                "A bomb threat has been received via phone. The caller provided specific details about the device location. What is the appropriate immediate action?"
            ],
            'D5': [
                "During an investigation of theft, you discover evidence that implicates a senior manager. How should you proceed?",
                "A witness to a security incident is reluctant to provide information due to fear of retaliation. What is the best approach?"
            ],
            'D6': [
                "Your organization is subject to a regulatory audit and investigators are requesting access to security logs. What should be your primary concern?",
                "A contract security guard has violated company policy but claims they were following orders from their supervisor. How should this be addressed?"
            ],
            'D7': [
                "You discover that a colleague is falsifying security reports to avoid additional work. What is the most appropriate action?",
                "A client is asking you to perform activities that may violate professional ethical standards. How should you respond?"
            ]
        }
        return scenarios.get(domain, ["Generic scenario question"])[index % len(scenarios.get(domain, ["Generic"]))]
    
    @staticmethod
    def _generate_scenario_options(domain: str, index: int) -> List[str]:
        """Generate scenario answer options"""
        option_sets = [
            ["Implement a comprehensive solution addressing root causes", "Apply temporary fixes", "Ignore the issue", "Escalate without action"],
            ["Follow established procedures and protocols", "Take immediate action", "Consult with legal counsel", "Document and report"],
            ["Prioritize safety and security", "Focus on business continuity", "Minimize disruption", "Maintain confidentiality"],
            ["Investigate thoroughly before acting", "Take immediate corrective action", "Seek guidance from supervision", "Document the incident"]
        ]
        return option_sets[index % len(option_sets)]
    
    @staticmethod
    def _generate_explanation(domain: str, index: int, question_type: str) -> str:
        """Generate detailed explanations for answers"""
        explanations = {
            'D1': "Physical security principles emphasize defense in depth, risk-based approaches, and integration of multiple security measures.",
            'D2': "Personnel security focuses on comprehensive screening, continuous monitoring, and maintaining the human element of security.",
            'D3': "Information systems security requires layered defenses, regular updates, and strong access controls to protect digital assets.",
            'D4': "Crisis management prioritizes life safety, clear communication, and following established emergency procedures.",
            'D5': "Investigations must maintain evidence integrity, objective analysis, and proper documentation for legal validity.",
            'D6': "Legal and regulatory compliance requires understanding applicable laws, proper documentation, and professional guidance.",
            'D7': "Professional ethics demand integrity, competence, and putting public safety and professional standards above personal interests."
        }
        return explanations.get(domain, "This answer follows established security principles and best practices.")
    
    @staticmethod
    def _get_default_flashcards() -> Dict[str, dict]:
        """Generate comprehensive flashcard set with 150+ cards"""
        flashcards = {}
        card_id = 1
        
        # Domain-based flashcard distribution
        domain_cards = {
            'D1': 35, 'D2': 25, 'D3': 15, 'D4': 20,
            'D5': 25, 'D6': 20, 'D7': 20
        }
        
        for domain, count in domain_cards.items():
            for i in range(count):
                flashcards[str(card_id)] = {
                    'id': str(card_id),
                    'domain': domain,
                    'front': ContentEngine._generate_flashcard_front(domain, i),
                    'back': ContentEngine._generate_flashcard_back(domain, i),
                    'difficulty': random.randint(1, 5),
                    'repetitions': 0,
                    'ease_factor': 2.5,
                    'interval': 1,
                    'due_date': dt.now().isoformat(),
                    'last_reviewed': ''
                }
                card_id += 1
        
        return flashcards
    
    @staticmethod
    def _generate_flashcard_front(domain: str, index: int) -> str:
        """Generate flashcard front (question/term)"""
        fronts = {
            'D1': [
                "Defense in Depth", "CPTED", "Access Control", "Perimeter Security", "Intrusion Detection",
                "Video Surveillance", "Lighting Standards", "Barrier Types", "Lock Classifications", "Key Management"
            ],
            'D2': [
                "Security Clearance Levels", "Background Investigations", "Insider Threat", "Security Awareness",
                "Personnel Screening", "Continuous Monitoring", "Access Termination", "Security Training"
            ],
            'D3': [
                "Network Security", "Encryption Standards", "Access Controls", "Vulnerability Management",
                "Incident Response", "Data Classification", "Backup Procedures", "Security Monitoring"
            ],
            'D4': [
                "Crisis Management", "Emergency Response", "Business Continuity", "Disaster Recovery",
                "Incident Command", "Communication Plans", "Evacuation Procedures", "Risk Assessment"
            ],
            'D5': [
                "Evidence Handling", "Chain of Custody", "Investigation Techniques", "Interview Methods",
                "Surveillance Operations", "Documentation Standards", "Legal Procedures", "Report Writing"
            ],
            'D6': [
                "Legal Compliance", "Regulatory Requirements", "Contract Law", "Privacy Laws",
                "Employment Law", "Liability Issues", "Professional Standards", "Audit Procedures"
            ],
            'D7': [
                "Professional Ethics", "Code of Conduct", "Continuing Education", "Professional Development",
                "Conflict of Interest", "Confidentiality", "Professional Certification", "Best Practices"
            ]
        }
        domain_fronts = fronts.get(domain, ["Generic Term"])
        return domain_fronts[index % len(domain_fronts)]
    
    @staticmethod
    def _generate_flashcard_back(domain: str, index: int) -> str:
        """Generate flashcard back (definition/answer)"""
        backs = {
            'D1': [
                "Multiple layers of security controls to protect assets",
                "Crime Prevention Through Environmental Design",
                "Methods to regulate who can access facilities or information",
                "Security measures at the boundary of protected areas",
                "Systems that detect unauthorized access attempts"
            ],
            'D2': [
                "Confidential, Secret, and Top Secret classification levels",
                "Process of verifying individual backgrounds and suitability",
                "Security risk posed by authorized personnel",
                "Training to help employees recognize and respond to security threats",
                "Process of evaluating personnel for security positions"
            ],
            'D3': [
                "Protection of computer networks and systems from cyber threats",
                "Methods for encoding data to prevent unauthorized access",
                "Systems that restrict access to authorized users only",
                "Process of identifying and addressing security weaknesses",
                "Organized approach to managing security incidents"
            ],
            'D4': [
                "Coordinated response to emergency situations",
                "Immediate actions taken during emergency situations",
                "Plans to maintain operations during disruptions",
                "Process of restoring operations after disasters",
                "Structured approach to emergency management"
            ],
            'D5': [
                "Proper procedures for collecting and preserving evidence",
                "Documentation of evidence handling from collection to court",
                "Systematic methods for gathering information and facts",
                "Structured approaches to questioning witnesses and suspects",
                "Covert observation and monitoring activities"
            ],
            'D6': [
                "Adherence to applicable laws and regulations",
                "Legal standards that organizations must follow",
                "Legal agreements between parties for services",
                "Regulations protecting individual privacy rights",
                "Laws governing workplace relationships and practices"
            ],
            'D7': [
                "Moral principles governing professional conduct",
                "Standards of behavior expected from security professionals",
                "Ongoing learning requirements for professional development",
                "Activities to enhance professional knowledge and skills",
                "Situations where personal interests may compromise professional judgment"
            ]
        }
        domain_backs = backs.get(domain, ["Generic Definition"])
        return domain_backs[index % len(domain_backs)]

# Bind ContentEngine methods to DataManager
def _get_default_questions(self) -> Dict[str, dict]:
    return ContentEngine._get_default_questions()

def _get_default_flashcards(self) -> Dict[str, dict]:
    return ContentEngine._get_default_flashcards()

DataManager._get_default_questions = _get_default_questions
DataManager._get_default_flashcards = _get_default_flashcards
# Spaced Repetition Algorithm (SM-2 based)
class SpacedRepetition:
    @staticmethod
    def calculate_next_review(flashcard: Flashcard, quality: int) -> Flashcard:
        """Calculate next review date based on SM-2 algorithm"""
        if quality < 3:
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
        
        flashcard.ease_factor = max(1.3, flashcard.ease_factor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02)))
        flashcard.due_date = (dt.now() + timedelta(days=flashcard.interval)).isoformat()
        flashcard.last_reviewed = dt.now().isoformat()
        
        return flashcard

# Progress Analytics Engine
class ProgressAnalytics:
    @staticmethod
    def calculate_overall_progress(user_id: str) -> Dict[str, Any]:
        """Calculate comprehensive progress metrics"""
        quiz_attempts = data_manager.get_user_quiz_attempts(user_id)
        exam_attempts = data_manager.get_user_exam_attempts(user_id)
        
        if not quiz_attempts and not exam_attempts:
            return {
                'overall_score': 0,
                'domain_scores': {domain: 0 for domain in CPP_DOMAINS.keys()},
                'progress_percentage': 0,
                'study_streak': 0,
                'weak_domains': [],
                'strong_domains': [],
                'recommendation': 'Start with practice quizzes to assess your knowledge'
            }
        
        # Calculate domain scores
        domain_scores = {}
        for domain in CPP_DOMAINS.keys():
            domain_attempts = [att for att in quiz_attempts + exam_attempts if domain in att.domain_scores]
            if domain_attempts:
                recent_scores = [att.domain_scores[domain] for att in domain_attempts[-5:]]
                domain_scores[domain] = sum(recent_scores) / len(recent_scores)
            else:
                domain_scores[domain] = 0
        
        overall_score = sum(domain_scores.values()) / len(domain_scores) if domain_scores else 0
        progress_percentage = min(100, overall_score * 100)
        
        # Identify weak and strong domains
        sorted_domains = sorted(domain_scores.items(), key=lambda x: x[1])
        weak_domains = [domain for domain, score in sorted_domains[:3] if score < 0.7]
        strong_domains = [domain for domain, score in sorted_domains[-3:] if score >= 0.8]
        
        return {
            'overall_score': overall_score,
            'domain_scores': domain_scores,
            'progress_percentage': progress_percentage,
            'study_streak': ProgressAnalytics._calculate_study_streak(user_id),
            'weak_domains': weak_domains,
            'strong_domains': strong_domains,
            'recommendation': ProgressAnalytics._generate_recommendation(domain_scores, overall_score)
        }
    
    @staticmethod
    def _calculate_study_streak(user_id: str) -> int:
        """Calculate consecutive days of study activity"""
        # Simplified streak calculation
        attempts = data_manager.get_user_quiz_attempts(user_id) + data_manager.get_user_exam_attempts(user_id)
        if not attempts:
            return 0
        
        # Group by date and count consecutive days
        study_dates = set()
        for attempt in attempts:
            date = dt.fromisoformat(attempt.completed_at).date()
            study_dates.add(date)
        
        if not study_dates:
            return 0
        
        sorted_dates = sorted(study_dates, reverse=True)
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
    def _generate_recommendation(domain_scores: Dict[str, float], overall_score: float) -> str:
        """Generate personalized study recommendations"""
        if overall_score < 0.5:
            return "Focus on fundamental concepts across all domains. Start with flashcards to build knowledge base."
        elif overall_score < 0.7:
            weak_domains = [domain for domain, score in domain_scores.items() if score < 0.6]
            if weak_domains:
                domain_names = [CPP_DOMAINS[d]['name'] for d in weak_domains[:2]]
                return f"Concentrate on {' and '.join(domain_names)}. Take targeted quizzes in these areas."
            return "You're making good progress. Continue with mixed practice and focus on weak areas."
        else:
            return "Excellent progress! You're ready for full-length practice exams to test exam readiness."

# Authentication and Session Management
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        users = data_manager.get_users()
        user = users.get(session['user_id'])
        
        if not user or user.subscription_status != 'active':
            return redirect(url_for('billing'))
        
        # Check subscription expiry
        if user.subscription_expires and dt.fromisoformat(user.subscription_expires) < dt.now():
            user.subscription_status = 'expired'
            data_manager.save_user(user)
            return redirect(url_for('billing'))
        
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
    users = data_manager.get_users()
    return users.get(session['user_id'])

# Add ContentEngine methods to DataManager
def _get_default_questions(self) -> Dict[str, dict]:
    return ContentEngine._get_default_questions()

def _get_default_flashcards(self) -> Dict[str, dict]:
    return ContentEngine._get_default_flashcards()

# Bind methods to DataManager
# Continuing from Section 2 - last two lines:
DataManager._get_default_questions = _get_default_questions
DataManager._get_default_flashcards = _get_default_flashcards

# HTML Templates
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}CPP Test Prep Platform{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --info-color: #16a085;
        }
        
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .main-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            padding: 2rem;
            margin: 2rem auto;
            max-width: 1200px;
        }
        
        .navbar-custom {
            background: rgba(44, 62, 80, 0.95) !important;
            backdrop-filter: blur(10px);
            border-radius: 15px;
            margin: 1rem;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .btn-custom {
            background: linear-gradient(45deg, var(--secondary-color), var(--info-color));
            border: none;
            border-radius: 25px;
            padding: 10px 25px;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        .btn-custom:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            color: white;
        }
        
        .progress-speedometer {
            width: 200px;
            height: 200px;
            margin: 0 auto;
            position: relative;
        }
        
        .card-custom {
            background: rgba(255, 255, 255, 0.9);
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card-custom:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        
        .flashcard {
            perspective: 1000px;
            height: 200px;
            cursor: pointer;
        }
        
        .flashcard-inner {
            position: relative;
            width: 100%;
            height: 100%;
            text-align: center;
            transition: transform 0.6s;
            transform-style: preserve-3d;
        }
        
        .flashcard.flipped .flashcard-inner {
            transform: rotateY(180deg);
        }
        
        .flashcard-front, .flashcard-back {
            position: absolute;
            width: 100%;
            height: 100%;
            backface-visibility: hidden;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .flashcard-back {
            transform: rotateY(180deg);
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }
        
        .timer-display {
            font-size: 2rem;
            font-weight: bold;
            color: var(--danger-color);
            text-align: center;
            padding: 1rem;
            background: rgba(231, 76, 60, 0.1);
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        
        .question-nav {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
            gap: 5px;
            padding: 1rem;
            background: rgba(248, 249, 250, 0.8);
            border-radius: 10px;
            margin: 1rem 0;
        }
        
        .question-nav-btn {
            width: 40px;
            height: 40px;
            border: 2px solid #dee2e6;
            background: white;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
            font-weight: bold;
        }
        
        .question-nav-btn:hover {
            background: #e9ecef;
        }
        
        .question-nav-btn.answered {
            background: var(--success-color);
            color: white;
            border-color: var(--success-color);
        }
        
        .question-nav-btn.current {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        .question-nav-btn.marked {
            background: var(--warning-color);
            color: white;
            border-color: var(--warning-color);
        }
        
        .domain-progress {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .alert-custom {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .fade-in-up {
            animation: fadeInUp 0.6s ease-out;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
    </style>
    {% block extra_head %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom">
        <div class="container">
            <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt me-2"></i>CPP Test Prep
            </a>
            
            {% if session.user_id %}
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="{{ url_for('dashboard') }}">
                    <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                </a>
                <a class="nav-link" href="{{ url_for('quiz') }}">
                    <i class="fas fa-question-circle me-1"></i>Practice Quiz
                </a>
                <a class="nav-link" href="{{ url_for('mock_exam') }}">
                    <i class="fas fa-file-alt me-1"></i>Mock Exam
                </a>
                <a class="nav-link" href="{{ url_for('flashcards') }}">
                    <i class="fas fa-layer-group me-1"></i>Flashcards
                </a>
                <a class="nav-link" href="{{ url_for('ai_tutor') }}">
                    <i class="fas fa-robot me-1"></i>AI Tutor
                </a>
                <a class="nav-link" href="{{ url_for('billing') }}">
                    <i class="fas fa-credit-card me-1"></i>Billing
                </a>
                <a class="nav-link" href="{{ url_for('logout') }}">
                    <i class="fas fa-sign-out-alt me-1"></i>Logout
                </a>
            </div>
            {% endif %}
        </div>
    </nav>
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-custom alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="main-container fade-in-up">
            {% block content %}{% endblock %}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://js.stripe.com/v3/"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
"""

# Authentication Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return redirect(url_for('login'))
        
        users = data_manager.get_users()
        user = None
        for u in users.values():
            if u.username == username or u.email == username:
                user = u
                break
        
        if user and verify_password(password, user.password_hash):
            session['user_id'] = user.id
            user.last_login = dt.now().isoformat()
            data_manager.save_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    template = BASE_TEMPLATE + """
    {% block title %}Login - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card card-custom">
                <div class="card-body p-5">
                    <h2 class="text-center mb-4">
                        <i class="fas fa-shield-alt text-primary me-2"></i>
                        Login to CPP Test Prep
                    </h2>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username or Email</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-custom w-100 mb-3">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </form>
                    <div class="text-center">
                        <p>Don't have an account? <a href="{{ url_for('register') }}" class="text-decoration-none">Register here</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    return render_template_string(template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        users = data_manager.get_users()
        for user in users.values():
            if user.username == username:
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
            if user.email == email:
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
        
        # Create new user
        user_id = str(uuid.uuid4())
        new_user = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=hash_password(password),
            created_at=dt.now().isoformat()
        )
        
        data_manager.save_user(new_user)
        
        session['user_id'] = user_id
        flash('Registration successful! Welcome to CPP Test Prep!', 'success')
        return redirect(url_for('billing'))  # Direct to subscription
    
    template = BASE_TEMPLATE + """
    {% block title %}Register - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card card-custom">
                <div class="card-body p-5">
                    <h2 class="text-center mb-4">
                        <i class="fas fa-user-plus text-primary me-2"></i>
                        Create Your Account
                    </h2>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" 
                                   minlength="8" required>
                            <div class="form-text">Minimum 8 characters</div>
                        </div>
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="confirm_password" 
                                   name="confirm_password" required>
                        </div>
                        <button type="submit" class="btn btn-custom w-100 mb-3">
                            <i class="fas fa-user-plus me-2"></i>Create Account
                        </button>
                    </form>
                    <div class="text-center">
                        <p>Already have an account? <a href="{{ url_for('login') }}" class="text-decoration-none">Login here</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    return render_template_string(template)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    progress = ProgressAnalytics.calculate_overall_progress(user.id)
    
    # Get recent attempts
    quiz_attempts = data_manager.get_user_quiz_attempts(user.id)[:5]
    exam_attempts = data_manager.get_user_exam_attempts(user.id)[:5]
    
    template = BASE_TEMPLATE + """
    {% block title %}Dashboard - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row">
        <div class="col-12">
            <h1 class="mb-4">
                <i class="fas fa-tachometer-alt text-primary me-2"></i>
                Welcome back, {{ user.username }}!
            </h1>
        </div>
    </div>
    
    <div class="row">
        <!-- Progress Overview -->
        <div class="col-md-4">
            <div class="card card-custom">
                <div class="card-body text-center">
                    <h5 class="card-title">Overall Progress</h5>
                    <div class="progress-speedometer mb-3">
                        <svg width="200" height="200" viewBox="0 0 200 200">
                            <circle cx="100" cy="100" r="80" fill="none" stroke="#e9ecef" stroke-width="8"/>
                            <circle cx="100" cy="100" r="80" fill="none" stroke="#28a745" stroke-width="8"
                                    stroke-dasharray="{{ progress.progress_percentage * 5.02 }} 502"
                                    stroke-linecap="round" transform="rotate(-90 100 100)"/>
                            <text x="100" y="105" text-anchor="middle" class="h3 fw-bold">
                                {{ "%.0f"|format(progress.progress_percentage) }}%
                            </text>
                        </svg>
                    </div>
                    <p class="text-muted">{{ progress.recommendation }}</p>
                </div>
            </div>
        </div>
        
        <!-- Quick Stats -->
        <div class="col-md-8">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <div class="card card-custom">
                        <div class="card-body text-center">
                            <i class="fas fa-fire text-warning fa-2x mb-2"></i>
                            <h5>Study Streak</h5>
                            <h3 class="text-warning">{{ progress.study_streak }}</h3>
                            <small class="text-muted">Days</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card card-custom">
                        <div class="card-body text-center">
                            <i class="fas fa-trophy text-success fa-2x mb-2"></i>
                            <h5>Quiz Attempts</h5>
                            <h3 class="text-success">{{ user.quiz_attempts }}</h3>
                            <small class="text-muted">Completed</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card card-custom">
                        <div class="card-body text-center">
                            <i class="fas fa-file-alt text-info fa-2x mb-2"></i>
                            <h5>Mock Exams</h5>
                            <h3 class="text-info">{{ user.exam_attempts }}</h3>
                            <small class="text-muted">Taken</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card card-custom">
                        <div class="card-body text-center">
                            <i class="fas fa-clock text-primary fa-2x mb-2"></i>
                            <h5>Study Time</h5>
                            <h3 class="text-primary">{{ "%.1f"|format(user.total_study_time / 3600) }}</h3>
                            <small class="text-muted">Hours</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Domain Performance -->
    <div class="row mt-4">
        <div class="col-12">
            <div class="card card-custom">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-chart-bar me-2"></i>Domain Performance
                    </h5>
                </div>
                <div class="card-body">
                    {% for domain_id, domain_info in domains.items() %}
                    <div class="domain-progress">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <strong>{{ domain_info.name }}</strong>
                            <span class="badge bg-primary">{{ "%.0f"|format(progress.domain_scores[domain_id] * 100) }}%</span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar" role="progressbar" 
                                 style="width: {{ progress.domain_scores[domain_id] * 100 }}%"
                                 aria-valuenow="{{ progress.domain_scores[domain_id] * 100 }}" 
                                 aria-valuemin="0" aria-valuemax="100">
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="row mt-4">
        <div class="col-12">
            <div class="card card-custom">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-rocket me-2"></i>Continue Your Journey
                    </h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3 mb-3">
                            <a href="{{ url_for('quiz') }}" class="btn btn-custom w-100 h-100 d-flex flex-column justify-content-center">
                                <i class="fas fa-question-circle fa-2x mb-2"></i>
                                <span>Practice Quiz</span>
                            </a>
                        </div>
                        <div class="col-md-3 mb-3">
                            <a href="{{ url_for('mock_exam') }}" class="btn btn-custom w-100 h-100 d-flex flex-column justify-content-center">
                                <i class="fas fa-file-alt fa-2x mb-2"></i>
                                <span>Mock Exam</span>
                            </a>
                        </div>
                        <div class="col-md-3 mb-3">
                            <a href="{{ url_for('flashcards') }}" class="btn btn-custom w-100 h-100 d-flex flex-column justify-content-center">
                                <i class="fas fa-layer-group fa-2x mb-2"></i>
                                <span>Flashcards</span>
                            </a>
                        </div>
                        <div class="col-md-3 mb-3">
                            <a href="{{ url_for('ai_tutor') }}" class="btn btn-custom w-100 h-100 d-flex flex-column justify-content-center">
                                <i class="fas fa-robot fa-2x mb-2"></i>
                                <span>AI Tutor</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    return render_template_string(template, 
                                user=user, 
                                progress=progress, 
                                domains=CPP_DOMAINS,
                                quiz_attempts=quiz_attempts,
                                exam_attempts=exam_attempts)

# Quiz Routes
@app.route('/quiz')
@login_required
@subscription_required
def quiz():
    template = BASE_TEMPLATE + """
    {% block title %}Practice Quiz - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card card-custom">
                <div class="card-header">
                    <h4 class="mb-0">
                        <i class="fas fa-question-circle text-primary me-2"></i>
                        Practice Quiz Setup
                    </h4>
                </div>
                <div class="card-body">
                    <form id="quizForm" action="{{ url_for('start_quiz') }}" method="POST">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="question_count" class="form-label">Number of Questions</label>
                                    <select class="form-control" id="question_count" name="question_count" required>
                                        <option value="10">10 Questions (Quick Review)</option>
                                        <option value="25" selected>25 Questions (Standard)</option>
                                        <option value="50">50 Questions (Extended)</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="domain" class="form-label">Focus Domain</label>
                                    <select class="form-control" id="domain" name="domain">
                                        <option value="">All Domains (Mixed)</option>
                                        {% for domain_id, domain_info in domains.items() %}
                                        <option value="{{ domain_id }}">{{ domain_info.name }}</option>
                                        {% endfor %}
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Question Types</label>
                            <div class="row">
                                <div class="col-md-4">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="multiple_choice" 
                                               name="question_types" value="multiple_choice" checked>
                                        <label class="form-check-label" for="multiple_choice">
                                            Multiple Choice
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="true_false" 
                                               name="question_types" value="true_false" checked>
                                        <label class="form-check-label" for="true_false">
                                            True/False
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="scenario" 
                                               name="question_types" value="scenario" checked>
                                        <label class="form-check-label" for="scenario">
                                            Scenario Based
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-custom btn-lg">
                                <i class="fas fa-play me-2"></i>Start Practice Quiz
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    return render_template_string(template, domains=CPP_DOMAINS)

@app.route('/start_quiz', methods=['POST'])
@login_required
@subscription_required
def start_quiz():
    question_count = int(request.form.get('question_count', 25))
    domain = request.form.get('domain', '')
    question_types = request.form.getlist('question_types')
    
    if not question_types:
        flash('Please select at least one question type', 'error')
        return redirect(url_for('quiz'))
    
    # Get questions
    all_questions = data_manager.get_questions()
    
    # Filter by domain and type
    filtered_questions = []
    for q in all_questions.values():
        if domain and q.domain != domain:
            continue
        if q.type not in question_types:
            continue
        filtered_questions.append(q)
    
    if len(filtered_questions) < question_count:
        flash(f'Not enough questions available. Only {len(filtered_questions)} questions found.', 'warning')
        question_count = len(filtered_questions)
    
    # Select random questions
    selected_questions = random.sample(filtered_questions, min(question_count, len(filtered_questions)))
    
    # Store quiz session
    session['quiz_questions'] = [q.id for q in selected_questions]
    session['quiz_answers'] = {}
    session['quiz_start_time'] = time.time()
    session['current_question'] = 0
    
    return redirect(url_for('take_quiz'))

@app.route('/take_quiz')
@login_required
@subscription_required
def take_quiz():
    if 'quiz_questions' not in session:
        return redirect(url_for('quiz'))
    
    current_idx = session.get('current_question', 0)
    question_ids = session['quiz_questions']
    
    if current_idx >= len(question_ids):
        return redirect(url_for('quiz_results'))
    
    questions = data_manager.get_questions()
    current_question = questions[question_ids[current_idx]]
    
    # Calculate time remaining (1 hour max)
    start_time = session.get('quiz_start_time', time.time())
    elapsed = time.time() - start_time
    time_remaining = max(0, app.config['MAX_QUIZ_TIME'] - elapsed)
    
    template = BASE_TEMPLATE + """
    {% block title %}Quiz Question {{ current_idx + 1 }} - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="timer-display" id="timer">
        Time Remaining: <span id="timeDisplay">{{ time_remaining }}</span>
    </div>
    
    <div class="row">
        <div class="col-md-9">
            <div class="card card-custom">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Question {{ current_idx + 1 }} of {{ total_questions }}</h5>
                    <div>
                        <span class="badge bg-primary">{{ question.domain }}</span>
                        <span class="badge bg-secondary">{{ question.type.replace('_', ' ').title() }}</span>
                    </div>
                </div>
                <div class="card-body">
                    <form id="answerForm" method="POST" action="{{ url_for('submit_quiz_answer') }}">
                        <div class="mb-4">
                            <h6>{{ question.question }}</h6>
                        </div>
                        
                        <div class="mb-4">
                            {% for option in question.options %}
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="radio" name="answer" 
                                       id="option{{ loop.index0 }}" value="{{ option }}"
                                       {% if current_answer == option %}checked{% endif %}>
                                <label class="form-check-label" for="option{{ loop.index0 }}">
                                    {{ option }}
                                </label>
                            </div>
                            {% endfor %}
                        </div>
                        
                        <div class="d-flex justify-content-between">
                            {% if current_idx > 0 %}
                            <button type="button" class="btn btn-outline-secondary" onclick="previousQuestion()">
                                <i class="fas fa-arrow-left me-2"></i>Previous
                            </button>
                            {% else %}
                            <div></div>
                            {% endif %}
                            
                            <div>
                                <button type="submit" name="action" value="save" class="btn btn-outline-primary me-2">
                                    Save Answer
                                </button>
                                {% if current_idx < total_questions - 1 %}
                                <button type="submit" name="action" value="next" class="btn btn-custom">
                                    Next <i class="fas fa-arrow-right ms-2"></i>
                                </button>
                                {% else %}
                                <button type="submit" name="action" value="finish" class="btn btn-success">
                                    <i class="fas fa-check me-2"></i>Finish Quiz
                                </button>
                                {% endif %}
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card card-custom">
                <div class="card-header">
                    <h6 class="mb-0">Question Navigation</h6>
                </div>
                <div class="card-body p-2">
                    <div class="question-nav">
                        {% for i in range(total_questions) %}
                        <div class="question-nav-btn {% if i == current_idx %}current{% elif question_ids[i] in answers %}answered{% endif %}"
                             onclick="goToQuestion({{ i }})">
                            {{ i + 1 }}
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    
    {% block scripts %}
    <script>
        let timeRemaining = {{ time_remaining }};
        
        function updateTimer() {
            if (timeRemaining <= 0) {
                document.getElementById('answerForm').submit();
                return;
            }
            
            const hours = Math.floor(timeRemaining / 3600);
            const minutes = Math.floor((timeRemaining % 3600) / 60);
            const seconds = timeRemaining % 60;
            
            document.getElementById('timeDisplay').textContent = 
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            timeRemaining--;
        }
        
        setInterval(updateTimer, 1000);
        updateTimer();
        
        function previousQuestion() {
            window.location.href = '{{ url_for("take_quiz") }}?question=' + {{ current_idx - 1 }};
        }
        
        function goToQuestion(index) {
            window.location.href = '{{ url_for("take_quiz") }}?question=' + index;
        }
        
        // Auto-save functionality
        document.querySelectorAll('input[name="answer"]').forEach(input => {
            input.addEventListener('change', function() {
                setTimeout(() => {
                    const formData = new FormData();
                    formData.append('answer', this.value);
                    formData.append('action', 'save');
                    
                    fetch('{{ url_for("submit_quiz_answer") }}', {
                        method: 'POST',
                        body: formData
                    });
                }, 100);
            });
        });
    </script>
    {% endblock %}
    """
    
    # Handle question navigation
    question_param = request.args.get('question')
    if question_param is not None:
        try:
            new_idx = int(question_param)
            if 0 <= new_idx < len(question_ids):
                session['current_question'] = new_idx
                current_idx = new_idx
                current_question = questions[question_ids[current_idx]]
        except ValueError:
            pass
    
    current_answer = session['quiz_answers'].get(question_ids[current_idx], '')
    
    return render_template_string(template,
                                current_idx=current_idx,
                                question=current_question,
                                total_questions=len(question_ids),
                                question_ids=question_ids,
                                answers=session['quiz_answers'],
                                current_answer=current_answer,
                                time_remaining=int(time_remaining))

@app.route('/submit_quiz_answer', methods=['POST'])
@login_required
@subscription_required
def submit_quiz_answer():
    if 'quiz_questions' not in session:
        return redirect(url_for('quiz'))
    
    answer = request.form.get('answer', '')
    action = request.form.get('action', 'save')
    
    current_idx = session.get('current_question', 0)
    question_ids = session['quiz_questions']
    
    # Save answer
    if answer:
        session['quiz_answers'][question_ids[current_idx]] = answer
    
    if action == 'next' and current_idx < len(question_ids) - 1:
        session['current_question'] = current_idx + 1
        return redirect(url_for('take_quiz'))
    elif action == 'finish' or current_idx >= len(question_ids) - 1:
        return redirect(url_for('quiz_results'))
    
    return redirect(url_for('take_quiz'))

@app.route('/quiz_results')
@login_required
@subscription_required
def quiz_results():
    if 'quiz_questions' not in session:
        return redirect(url_for('quiz'))
    
    # Calculate results
    questions = data_manager.get_questions()
    question_ids = session['quiz_questions']
    answers = session['quiz_answers']
    start_time = session.get('quiz_start_time', time.time())
    
    correct_count = 0
    domain_stats = {}
    results = []
    
    for domain in CPP_DOMAINS.keys():
        domain_stats[domain] = {'correct': 0, 'total': 0}
    
    for qid in question_ids:
        question = questions[qid]
        user_answer = answers.get(qid, '')
        is_correct = user_answer == question.correct_answer
        
        if is_correct:
            correct_count += 1
            domain_stats[question.domain]['correct'] += 1
        
        domain_stats[question.domain]['total'] += 1
        
        results.append({
            'question': question,
            'user_answer': user_answer,
            'correct': is_correct
        })
    
    # Calculate domain scores
    domain_scores = {}
    for domain, stats in domain_stats.items():
        if stats['total'] > 0:
            domain_scores[domain] = stats['correct'] / stats['total']
        else:
            domain_scores[domain] = 0
    
    total_questions = len(question_ids)
    score = correct_count / total_questions if total_questions > 0 else 0
    time_taken = int(time.time() - start_time)
    
    # Save quiz attempt
    user = get_current_user()
    attempt = QuizAttempt(
        id=str(uuid.uuid4()),
        user_id=user.id,
        questions=question_ids,
        answers=answers,
        score=score,
        domain_scores=domain_scores,
        completed_at=dt.now().isoformat(),
        time_taken=time_taken,
        quiz_type='practice'
    )
    
    data_manager.save_quiz_attempt(attempt)
    
    # Update user stats
    user.quiz_attempts += 1
    user.total_study_time += time_taken
    data_manager.save_user(user)
    
    # Clear session
    for key in ['quiz_questions', 'quiz_answers', 'quiz_start_time', 'current_question']:
        session.pop(key, None)
    
    template = BASE_TEMPLATE + """
    {% block title %}Quiz Results - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-10">
            <div class="card card-custom">
                <div class="card-header">
                    <h4 class="mb-0">
                        <i class="fas fa-chart-line text-primary me-2"></i>
                        Quiz Results
                    </h4>
                </div>
                <div class="card-body">
                    <!-- Score Summary -->
                    <div class="row mb-4">
                        <div class="col-md-3 text-center">
                            <div class="card bg-{% if score >= 0.7 %}success{% elif score >= 0.5 %}warning{% else %}danger{% endif %} text-white">
                                <div class="card-body">
                                    <h2>{{ "%.0f"|format(score * 100) }}%</h2>
                                    <p class="mb-0">Overall Score</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-info text-white">
                                <div class="card-body">
                                    <h2>{{ correct_count }}/{{ total_questions }}</h2>
                                    <p class="mb-0">Correct Answers</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-primary text-white">
                                <div class="card-body">
                                    <h2>{{ "%.0f"|format(time_taken / 60) }}</h2>
                                    <p class="mb-0">Minutes</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-secondary text-white">
                                <div class="card-body">
                                    <h2>{{ "%.1f"|format(time_taken / total_questions) }}</h2>
                                    <p class="mb-0">Sec/Question</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Domain Performance -->
                    <div class="mb-4">
                        <h5>Domain Performance</h5>
                        {% for domain_id, domain_info in domains.items() %}
                        {% if domain_stats[domain_id].total > 0 %}
                        <div class="domain-progress">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <strong>{{ domain_info.name }}</strong>
                                <span class="badge bg-primary">
                                    {{ domain_stats[domain_id].correct }}/{{ domain_stats[domain_id].total }}
                                    ({{ "%.0f"|format(domain_scores[domain_id] * 100) }}%)
                                </span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar {% if domain_scores[domain_id] >= 0.7 %}bg-success{% elif domain_scores[domain_id] >= 0.5 %}bg-warning{% else %}bg-danger{% endif %}" 
                                     role="progressbar" style="width: {{ domain_scores[domain_id] * 100 }}%">
                                </div>
                            </div>
                        </div>
                        {% endif %}
                        {% endfor %}
                    </div>
                    
                    <!-- Recommendations -->
                    <div class="alert alert-custom alert-info">
                        <h6><i class="fas fa-lightbulb me-2"></i>Study Recommendations</h6>
                        {% if score >= 0.7 %}
                        <p>Excellent work! You're ready for more challenging practice or a mock exam.</p>
                        {% elif score >= 0.5 %}
                        <p>Good progress! Focus on improving weak domains and continue regular practice.</p>
                        {% else %}
                        <p>Keep studying! Review fundamental concepts and use flashcards to strengthen your knowledge.</p>
                        {% endif %}
                        
                        {% set weak_domains = [] %}
                        {% for domain_id, score_val in domain_scores.items() %}
                            {% if score_val < 0.6 and domain_stats[domain_id].total > 0 %}
                                {% set _ = weak_domains.append(domain_id) %}
                            {% endif %}
                        {% endfor %}
                        
                        {% if weak_domains %}
                        <p><strong>Focus Areas:</strong> 
                        {% for domain_id in weak_domains %}
                            {{ domains[domain_id].name }}{% if not loop.last %}, {% endif %}
                        {% endfor %}
                        </p>
                        {% endif %}
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="d-flex justify-content-center gap-3">
                        <a href="{{ url_for('quiz') }}" class="btn btn-custom">
                            <i class="fas fa-redo me-2"></i>Take Another Quiz
                        </a>
                        <a href="{{ url_for('flashcards') }}" class="btn btn-outline-primary">
                            <i class="fas fa-layer-group me-2"></i>Study Flashcards
                        </a>
                        <a href="{{ url_for('mock_exam') }}" class="btn btn-outline-success">
                            <i class="fas fa-file-alt me-2"></i>Take Mock Exam
                        </a>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    return render_template_string(template,
                                score=score,
                                correct_count=correct_count,
                                total_questions=total_questions,
                                time_taken=time_taken,
                                domain_scores=domain_scores,
                                domain_stats=domain_stats,
                                domains=CPP_DOMAINS,
                                results=results)

# Health Check Routes
@app.route('/health')
@app.route('/healthz')
@app.route('/ready')
def health_check():
    """Health check endpoint for deployment"""
    return jsonify({
        'status': 'healthy',
        'timestamp': dt.now().isoformat(),
        # Continuing from Section 3 - last two lines:
        # Continuing from Section 3 - last two lines:
        'service': 'CPP Test Prep Platform'
    })

# Mock Exam System
@app.route('/mock_exam')
@login_required
@subscription_required
def mock_exam():
    template = BASE_TEMPLATE + """
    {% block title %}Mock Exam - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card card-custom">
                <div class="card-header">
                    <h4 class="mb-0">
                        <i class="fas fa-file-alt text-primary me-2"></i>
                        CPP Mock Examination
                    </h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <h6><i class="fas fa-info-circle me-2"></i>Exam Instructions</h6>
                        <ul>
                            <li>Choose your exam length below</li>
                            <li>Questions are distributed across all CPP domains</li>
                            <li>You have 3 hours maximum to complete</li>
                            <li>70% is required to pass</li>
                            <li>No feedback is provided during the exam</li>
                            <li>You can mark questions for review</li>
                        </ul>
                    </div>
                    
                    <form action="{{ url_for('start_mock_exam') }}" method="POST">
                        <div class="mb-4">
                            <label class="form-label">Select Exam Length</label>
                            <div class="row">
                                <div class="col-md-4 mb-2">
                                    <div class="card text-center">
                                        <div class="card-body">
                                            <input type="radio" name="question_count" value="25" id="exam25" class="form-check-input">
                                            <label for="exam25" class="form-check-label d-block">
                                                <h5>25 Questions</h5>
                                                <small class="text-muted">Quick Practice</small>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4 mb-2">
                                    <div class="card text-center">
                                        <div class="card-body">
                                            <input type="radio" name="question_count" value="75" id="exam75" class="form-check-input" checked>
                                            <label for="exam75" class="form-check-label d-block">
                                                <h5>75 Questions</h5>
                                                <small class="text-muted">Half Exam</small>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4 mb-2">
                                    <div class="card text-center">
                                        <div class="card-body">
                                            <input type="radio" name="question_count" value="150" id="exam150" class="form-check-input">
                                            <label for="exam150" class="form-check-label d-block">
                                                <h5>150 Questions</h5>
                                                <small class="text-muted">Full Exam</small>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-custom btn-lg">
                                <i class="fas fa-play me-2"></i>Start Mock Exam
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    return render_template_string(template)

@app.route('/start_mock_exam', methods=['POST'])
@login_required
@subscription_required
def start_mock_exam():
    question_count = int(request.form.get('question_count', 75))
    
    # Get questions distributed by domain according to CPP weights
    all_questions = data_manager.get_questions()
    domain_questions = {domain: [] for domain in CPP_DOMAINS.keys()}
    
    for q in all_questions.values():
        domain_questions[q.domain].append(q)
    
    # Select questions based on domain weights
    selected_questions = []
    for domain, weight in CPP_DOMAINS.items():
        domain_count = int(question_count * weight['weight'])
        available = domain_questions[domain]
        if available:
            selected = random.sample(available, min(domain_count, len(available)))
            selected_questions.extend(selected)
    
    # Fill remaining spots if needed
    while len(selected_questions) < question_count:
        remaining_questions = [q for q in all_questions.values() 
                             if q not in selected_questions]
        if not remaining_questions:
            break
        selected_questions.append(random.choice(remaining_questions))
    
    # Store exam session
    session['exam_questions'] = [q.id for q in selected_questions[:question_count]]
    session['exam_answers'] = {}
    session['exam_marked'] = set()
    session['exam_start_time'] = time.time()
    session['current_exam_question'] = 0
    
    return redirect(url_for('take_exam'))

@app.route('/take_exam')
@login_required
@subscription_required
def take_exam():
    if 'exam_questions' not in session:
        return redirect(url_for('mock_exam'))
    
    current_idx = session.get('current_exam_question', 0)
    question_ids = session['exam_questions']
    
    if current_idx >= len(question_ids):
        return redirect(url_for('exam_results'))
    
    questions = data_manager.get_questions()
    current_question = questions[question_ids[current_idx]]
    
    # Calculate time remaining (3 hours max)
    start_time = session.get('exam_start_time', time.time())
    elapsed = time.time() - start_time
    time_remaining = max(0, app.config['MAX_EXAM_TIME'] - elapsed)
    
    # Handle question navigation
    question_param = request.args.get('question')
    if question_param is not None:
        try:
            new_idx = int(question_param)
            if 0 <= new_idx < len(question_ids):
                session['current_exam_question'] = new_idx
                current_idx = new_idx
                current_question = questions[question_ids[current_idx]]
        except ValueError:
            pass
    
    current_answer = session['exam_answers'].get(question_ids[current_idx], '')
    is_marked = question_ids[current_idx] in session.get('exam_marked', set())
    
    template = BASE_TEMPLATE + """
    {% block title %}Mock Exam Question {{ current_idx + 1 }} - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="timer-display" id="timer">
        Time Remaining: <span id="timeDisplay">{{ time_remaining }}</span>
    </div>
    
    <div class="row">
        <div class="col-md-9">
            <div class="card card-custom">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Question {{ current_idx + 1 }} of {{ total_questions }}</h5>
                    <div>
                        <span class="badge bg-primary">{{ question.domain }}</span>
                        <button type="button" class="btn btn-sm {% if is_marked %}btn-warning{% else %}btn-outline-warning{% endif %}" 
                                onclick="toggleMark()">
                            <i class="fas fa-flag"></i> {% if is_marked %}Marked{% else %}Mark{% endif %}
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <form id="examForm" method="POST" action="{{ url_for('submit_exam_answer') }}">
                        <div class="mb-4">
                            <h6>{{ question.question }}</h6>
                        </div>
                        
                        <div class="mb-4">
                            {% for option in question.options %}
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="radio" name="answer" 
                                       id="option{{ loop.index0 }}" value="{{ option }}"
                                       {% if current_answer == option %}checked{% endif %}>
                                <label class="form-check-label" for="option{{ loop.index0 }}">
                                    {{ option }}
                                </label>
                            </div>
                            {% endfor %}
                        </div>
                        
                        <div class="d-flex justify-content-between">
                            {% if current_idx > 0 %}
                            <button type="button" class="btn btn-outline-secondary" onclick="previousQuestion()">
                                <i class="fas fa-arrow-left me-2"></i>Previous
                            </button>
                            {% else %}
                            <div></div>
                            {% endif %}
                            
                            <div>
                                {% if current_idx < total_questions - 1 %}
                                <button type="submit" name="action" value="next" class="btn btn-custom">
                                    Next <i class="fas fa-arrow-right ms-2"></i>
                                </button>
                                {% else %}
                                <button type="button" class="btn btn-success" onclick="confirmSubmit()">
                                    <i class="fas fa-check me-2"></i>Submit Exam
                                </button>
                                {% endif %}
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card card-custom">
                <div class="card-header">
                    <h6 class="mb-0">Question Navigation</h6>
                </div>
                <div class="card-body p-2">
                    <div class="question-nav">
                        {% for i in range(total_questions) %}
                        <div class="question-nav-btn 
                                    {% if i == current_idx %}current
                                    {% elif question_ids[i] in answers %}answered
                                    {% endif %}
                                    {% if question_ids[i] in marked %}marked{% endif %}"
                             onclick="goToQuestion({{ i }})">
                            {{ i + 1 }}
                        </div>
                        {% endfor %}
                    </div>
                    
                    <div class="mt-3">
                        <small class="text-muted">
                            <i class="fas fa-circle text-success me-1"></i>Answered<br>
                            <i class="fas fa-circle text-warning me-1"></i>Marked<br>
                            <i class="fas fa-circle text-primary me-1"></i>Current
                        </small>
                    </div>
                </div>
            </div>
            
            <div class="card card-custom mt-3">
                <div class="card-body text-center">
                    <button type="button" class="btn btn-success w-100" onclick="confirmSubmit()">
                        <i class="fas fa-check me-2"></i>Submit Exam
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Submit Confirmation Modal -->
    <div class="modal fade" id="submitModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Submit Exam</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to submit your exam?</p>
                    <p><strong>Answered:</strong> <span id="answeredCount">0</span> / {{ total_questions }}</p>
                    <p><strong>Marked for Review:</strong> <span id="markedCount">0</span></p>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        You cannot change your answers after submission.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Continue Exam</button>
                    <form method="POST" action="{{ url_for('submit_exam_answer') }}" style="display: inline;">
                        <button type="submit" name="action" value="submit" class="btn btn-success">
                            Submit Final Exam
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    
    {% block scripts %}
    <script>
        let timeRemaining = {{ time_remaining }};
        
        function updateTimer() {
            if (timeRemaining <= 0) {
                document.querySelector('form[action="{{ url_for("submit_exam_answer") }}"]').submit();
                return;
            }
            
            const hours = Math.floor(timeRemaining / 3600);
            const minutes = Math.floor((timeRemaining % 3600) / 60);
            const seconds = timeRemaining % 60;
            
            document.getElementById('timeDisplay').textContent = 
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            timeRemaining--;
        }
        
        setInterval(updateTimer, 1000);
        updateTimer();
        
        function previousQuestion() {
            window.location.href = '{{ url_for("take_exam") }}?question=' + {{ current_idx - 1 }};
        }
        
        function goToQuestion(index) {
            window.location.href = '{{ url_for("take_exam") }}?question=' + index;
        }
        
        function toggleMark() {
            fetch('{{ url_for("toggle_exam_mark") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({question_id: '{{ question_ids[current_idx] }}'})
            }).then(() => {
                location.reload();
            });
        }
        
        function confirmSubmit() {
            const answeredCount = document.querySelectorAll('.question-nav-btn.answered').length;
            const markedCount = document.querySelectorAll('.question-nav-btn.marked').length;
            
            document.getElementById('answeredCount').textContent = answeredCount;
            document.getElementById('markedCount').textContent = markedCount;
            
            new bootstrap.Modal(document.getElementById('submitModal')).show();
        }
        
        // Auto-save functionality
        document.querySelectorAll('input[name="answer"]').forEach(input => {
            input.addEventListener('change', function() {
                const formData = new FormData();
                formData.append('answer', this.value);
                formData.append('action', 'save');
                
                fetch('{{ url_for("submit_exam_answer") }}', {
                    method: 'POST',
                    body: formData
                });
            });
        });
    </script>
    {% endblock %}
    """
    
    return render_template_string(template,
                                current_idx=current_idx,
                                question=current_question,
                                total_questions=len(question_ids),
                                question_ids=question_ids,
                                answers=session['exam_answers'],
                                marked=session.get('exam_marked', set()),
                                current_answer=current_answer,
                                is_marked=is_marked,
                                time_remaining=int(time_remaining))

@app.route('/submit_exam_answer', methods=['POST'])
@login_required
@subscription_required
def submit_exam_answer():
    if 'exam_questions' not in session:
        return redirect(url_for('mock_exam'))
    
    answer = request.form.get('answer', '')
    action = request.form.get('action', 'save')
    
    current_idx = session.get('current_exam_question', 0)
    question_ids = session['exam_questions']
    
    # Save answer
    if answer:
        session['exam_answers'][question_ids[current_idx]] = answer
    
    if action == 'next' and current_idx < len(question_ids) - 1:
        session['current_exam_question'] = current_idx + 1
        return redirect(url_for('take_exam'))
    elif action == 'submit':
        return redirect(url_for('exam_results'))
    
    return redirect(url_for('take_exam'))

@app.route('/toggle_exam_mark', methods=['POST'])
@login_required
@subscription_required
def toggle_exam_mark():
    if 'exam_marked' not in session:
        session['exam_marked'] = set()
    
    data = request.get_json()
    question_id = data.get('question_id')
    
    marked = session['exam_marked']
    if question_id in marked:
        marked.remove(question_id)
    else:
        marked.add(question_id)
    
    session['exam_marked'] = marked
    return jsonify({'status': 'success'})

@app.route('/exam_results')
@login_required
@subscription_required
def exam_results():
    if 'exam_questions' not in session:
        return redirect(url_for('mock_exam'))
    
    # Calculate results
    questions = data_manager.get_questions()
    question_ids = session['exam_questions']
    answers = session['exam_answers']
    start_time = session.get('exam_start_time', time.time())
    
    correct_count = 0
    domain_stats = {}
    
    for domain in CPP_DOMAINS.keys():
        domain_stats[domain] = {'correct': 0, 'total': 0}
    
    for qid in question_ids:
        question = questions[qid]
        user_answer = answers.get(qid, '')
        is_correct = user_answer == question.correct_answer
        
        if is_correct:
            correct_count += 1
            domain_stats[question.domain]['correct'] += 1
        
        domain_stats[question.domain]['total'] += 1
    
    # Calculate domain scores
    domain_scores = {}
    for domain, stats in domain_stats.items():
        if stats['total'] > 0:
            domain_scores[domain] = stats['correct'] / stats['total']
        else:
            domain_scores[domain] = 0
    
    total_questions = len(question_ids)
    score = correct_count / total_questions if total_questions > 0 else 0
    time_taken = int(time.time() - start_time)
    passed = score >= app.config['PASS_THRESHOLD']
    
    # Save exam attempt
    user = get_current_user()
    attempt = ExamAttempt(
        id=str(uuid.uuid4()),
        user_id=user.id,
        questions=question_ids,
        answers=answers,
        score=score,
        domain_scores=domain_scores,
        completed_at=dt.now().isoformat(),
        time_taken=time_taken,
        passed=passed,
        question_count=total_questions
    )
    
    data_manager.save_exam_attempt(attempt)
    
    # Update user stats
    user.exam_attempts += 1
    user.total_study_time += time_taken
    data_manager.save_user(user)
    
    # Clear session
    for key in ['exam_questions', 'exam_answers', 'exam_start_time', 'current_exam_question', 'exam_marked']:
        session.pop(key, None)
    
    template = BASE_TEMPLATE + """
    {% block title %}Exam Results - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-10">
            <div class="card card-custom">
                <div class="card-header">
                    <h4 class="mb-0">
                        <i class="fas fa-certificate text-primary me-2"></i>
                        Mock Exam Results
                    </h4>
                </div>
                <div class="card-body">
                    <!-- Pass/Fail Banner -->
                    <div class="alert alert-{% if passed %}success{% else %}danger{% endif %} text-center mb-4">
                        <h2>
                            {% if passed %}
                            <i class="fas fa-check-circle me-2"></i>PASSED
                            {% else %}
                            <i class="fas fa-times-circle me-2"></i>NOT PASSED
                            {% endif %}
                        </h2>
                        <p class="mb-0">Score: {{ "%.1f"|format(score * 100) }}% ({{ correct_count }}/{{ total_questions }})</p>
                        <small>Passing score: 70%</small>
                    </div>
                    
                    <!-- Score Details -->
                    <div class="row mb-4">
                        <div class="col-md-3 text-center">
                            <div class="card bg-{% if passed %}success{% else %}danger{% endif %} text-white">
                                <div class="card-body">
                                    <h2>{{ "%.1f"|format(score * 100) }}%</h2>
                                    <p class="mb-0">Final Score</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-info text-white">
                                <div class="card-body">
                                    <h2>{{ correct_count }}</h2>
                                    <p class="mb-0">Correct</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-warning text-white">
                                <div class="card-body">
                                    <h2>{{ total_questions - correct_count }}</h2>
                                    <p class="mb-0">Incorrect</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="card bg-secondary text-white">
                                <div class="card-body">
                                    <h2>{{ "%.0f"|format(time_taken / 60) }}</h2>
                                    <p class="mb-0">Minutes</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Domain Breakdown -->
                    <div class="mb-4">
                        <h5>Domain Performance Analysis</h5>
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Correct/Total</th>
                                        <th>Percentage</th>
                                        <th>Performance</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for domain_id, domain_info in domains.items() %}
                                    {% if domain_stats[domain_id].total > 0 %}
                                    <tr>
                                        <td>{{ domain_info.name }}</td>
                                        <td>{{ domain_stats[domain_id].correct }}/{{ domain_stats[domain_id].total }}</td>
                                        <td>{{ "%.1f"|format(domain_scores[domain_id] * 100) }}%</td>
                                        <td>
                                            {% if domain_scores[domain_id] >= 0.8 %}
                                            <span class="badge bg-success">Excellent</span>
                                            {% elif domain_scores[domain_id] >= 0.7 %}
                                            <span class="badge bg-primary">Good</span>
                                            {% elif domain_scores[domain_id] >= 0.6 %}
                                            <span class="badge bg-warning">Fair</span>
                                            {% else %}
                                            <span class="badge bg-danger">Needs Work</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endif %}
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Study Recommendations -->
                    <div class="alert alert-info">
                        <h6><i class="fas fa-graduation-cap me-2"></i>Next Steps</h6>
                        {% if passed %}
                        <p><strong>Congratulations!</strong> You're well-prepared for the CPP exam. Continue practicing to maintain your knowledge level.</p>
                        {% else %}
                        <p><strong>Keep studying!</strong> Focus on your weak domains and retake practice exams to improve your score.</p>
                        {% endif %}
                        
                        <strong>Focus Areas:</strong>
                        {% set weak_domains = [] %}
                        {% for domain_id, score_val in domain_scores.items() %}
                            {% if score_val < 0.7 and domain_stats[domain_id].total > 0 %}
                                {% set _ = weak_domains.append(domains[domain_id].name) %}
                            {% endif %}
                        {% endfor %}
                        
                        {% if weak_domains %}
                        {{ weak_domains | join(', ') }}
                        {% else %}
                        All domains performing well!
                        {% endif %}
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="text-center">
                        <a href="{{ url_for('mock_exam') }}" class="btn btn-custom me-2">
                            <i class="fas fa-redo me-2"></i>Take Another Exam
                        </a>
                        <a href="{{ url_for('quiz') }}" class="btn btn-outline-primary me-2">
                            <i class="fas fa-question-circle me-2"></i>Practice Quiz
                        </a>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    return render_template_string(template,
                                score=score,
                                correct_count=correct_count,
                                total_questions=total_questions,
                                time_taken=time_taken,
                                passed=passed,
                                domain_scores=domain_scores,
                                domain_stats=domain_stats,
                                domains=CPP_DOMAINS)

# Flashcard System
@app.route('/flashcards')
@login_required
@subscription_required
def flashcards():
    # Get all flashcards
    all_flashcards = data_manager.get_flashcards()
    
    # Filter due cards (cards due for review)
    now = dt.now()
    due_cards = []
    for card in all_flashcards.values():
        if card.due_date:
            due_date = dt.fromisoformat(card.due_date)
            if due_date <= now:
                due_cards.append(card)
        else:
            due_cards.append(card)  # New cards
    
    # Group by domain
    domain_counts = {}
    for domain in CPP_DOMAINS.keys():
        domain_cards = [c for c in due_cards if c.domain == domain]
        domain_counts[domain] = len(domain_cards)
    
    template = BASE_TEMPLATE + """
    {% block title %}Flashcards - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row">
        <div class="col-12">
            <h2 class="mb-4">
                <i class="fas fa-layer-group text-primary me-2"></i>
                Study Flashcards
            </h2>
        </div>
    </div>
    
    <div class="row">
        <div class="col-md-8">
            <div class="card card-custom">
                <div class="card-header">
                    <h5 class="mb-0">Available Study Sessions</h5>
                </div>
                <div class="card-body">
                    {% if due_cards %}
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <a href="{{ url_for('study_flashcards') }}" class="text-decoration-none">
                                <div class="card border-primary">
                                    <div class="card-body text-center">
                                        <i class="fas fa-brain fa-3x text-primary mb-3"></i>
                                        <h5>Study Due Cards</h5>
                                        <p class="text-muted">{{ due_cards|length }} cards ready for review</p>
                                        <span class="badge bg-primary">All Domains</span>
                                    </div>
                                </div>
                            </a>
                        </div>
                        
                        {% for domain_id, domain_info in domains.items() %}
                        {% if domain_counts[domain_id] > 0 %}
                        <div class="col-md-6 mb-3">
                            <a href="{{ url_for('study_flashcards', domain=domain_id) }}" class="text-decoration-none">
                                <div class="card border-info">
                                    <div class="card-body text-center">
                                        <i class="fas fa-bookmark fa-2x text-info mb-2"></i>
                                        <h6>{{ domain_info.name }}</h6>
                                        <p class="text-muted small">{{ domain_counts[domain_id] }} cards due</p>
                                    </div>
                                </div>
                            </a>
                        </div>
                        {% endif %}
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="text-center py-4">
                        <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                        <h5>All caught up!</h5>
                        <p class="text-muted">No flashcards are due for review right now.</p>
                        <a href="{{ url_for('study_flashcards', domain='D1') }}" class="btn btn-outline-primary">
                            Review Anyway
                        </a>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card card-custom">
                <div class="card-header">
                    <h6 class="mb-0">Study Statistics</h6>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <strong>Total Cards Due:</strong>
                        <span class="badge bg-primary">{{ due_cards|length }}</span>
                    </div>
                    
                    {% for domain_id, domain_info in domains.items() %}
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <small>{{ domain_info.name }}:</small>
                        <span class="badge bg-light text-dark">{{ domain_counts[domain_id] }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="card card-custom mt-3">
                <div class="card-header">
                    <h6 class="mb-0">How Flashcards Work</h6>
                </div>
                <div class="card-body">
                    <small class="text-muted">
                        <ul class="ps-3">
                            <li>Cards use spaced repetition</li>
                            <li>Rate your confidence (1-5)</li>
                            <li>Good answers = longer intervals</li>
                            <li>Difficult cards appear more often</li>
                            <li>Study consistently for best results</li>
                        </ul>
                    </small>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    return render_template_string(template, 
                                due_cards=due_cards,
                                domains=CPP_DOMAINS,
                                domain_counts=domain_counts)

@app.route('/study_flashcards')
@login_required
@subscription_required
def study_flashcards():
    domain = request.args.get('domain', '')
    
    # Get flashcards
    all_flashcards = data_manager.get_flashcards()
    
    # Filter by domain if specified
    if domain:
        study_cards = [c for c in all_flashcards.values() if c.domain == domain]
    else:
        # Get due cards
        now = dt.now()
        study_cards = []
        for card in all_flashcards.values():
            if card.due_date:
                due_date = dt.fromisoformat(card.due_date)
                if due_date <= now:
                    study_cards.append(card)
            else:
                study_cards.append(card)
    
    if not study_cards:
        flash('No flashcards available for study', 'info')
        return redirect(url_for('flashcards'))
    
    # Store study session
    session['flashcard_deck'] = [c.id for c in study_cards]
    session['current_flashcard'] = 0
    session['flashcard_session_start'] = time.time()
    session['flashcard_stats'] = {'correct': 0, 'total': 0}
    
    return redirect(url_for('study_card'))

@app.route('/study_card')
@login_required
@subscription_required
def study_card():
    if 'flashcard_deck' not in session:
        return redirect(url_for('flashcards'))
    
    deck = session['flashcard_deck']
    current_idx = session.get('current_flashcard', 0)
    
    if current_idx >= len(deck):
        return redirect(url_for('flashcard_session_complete'))
    
    flashcards = data_manager.get_flashcards()
    current_card = flashcards[deck[current_idx]]
    
    template = BASE_TEMPLATE + """
    {% block title %}Study Flashcard {{ current_idx + 1 }} - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="text-center mb-3">
                <span class="badge bg-primary">{{ domains[card.domain].name }}</span>
                <span class="badge bg-secondary">Card {{ current_idx + 1 }} of {{ total_cards }}</span>
            </div>
            
            <div class="flashcard" id="flashcard" onclick="flipCard()">
                <div class="flashcard-inner" id="flashcardInner">
                    <div class="flashcard-front">
                        <h4>{{ card.front }}</h4>
                        <div class="mt-auto">
                            <small class="text-light">Click to reveal answer</small>
                        </div>
                    </div>
                    <div class="flashcard-back">
                        <div>{{ card.back }}</div>
                        <div class="mt-3">
                            <small class="text-light">How well did you know this?</small>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="responseButtons" class="text-center mt-4" style="display: none;">
                <h6>Rate your confidence:</h6>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-danger" onclick="rateCard(1)">
                        1 - No idea
                    </button>
                    <button type="button" class="btn btn-warning" onclick="rateCard(2)">
                        2 - Hard
                    </button>
                    <button type="button" class="btn btn-info" onclick="rateCard(3)">
                        3 - Good
                    </button>
                    <button type="button" class="btn btn-success" onclick="rateCard(4)">
                        4 - Easy
                    </button>
                    <button type="button" class="btn btn-primary" onclick="rateCard(5)">
                        5 - Perfect
                    </button>
                </div>
            </div>
            
            <div class="progress mt-4">
                <div class="progress-bar" role="progressbar" 
                     style="width: {{ ((current_idx + 1) / total_cards * 100) }}%">
                    {{ current_idx + 1 }} / {{ total_cards }}
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    
    {% block scripts %}
    <script>
        let isFlipped = false;
        
        function flipCard() {
            if (!isFlipped) {
                document.getElementById('flashcard').classList.add('flipped');
                document.getElementById('responseButtons').style.display = 'block';
                isFlipped = true;
            }
        }
        
        function rateCard(rating) {
            fetch('{{ url_for("rate_flashcard") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    card_id: '{{ card.id }}',
                    rating: rating
                })
            }).then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = '{{ url_for("study_card") }}';
                }
            });
        }
    </script>
    {% endblock %}
    """
    
    return render_template_string(template,
                                card=current_card,
                                current_idx=current_idx,
                                total_cards=len(deck),
                                domains=CPP_DOMAINS)

@app.route('/rate_flashcard', methods=['POST'])
@login_required
@subscription_required
def rate_flashcard():
    if 'flashcard_deck' not in session:
        return jsonify({'status': 'error', 'message': 'No active session'})
    
    data = request.get_json()
    card_id = data.get('card_id')
    rating = int(data.get('rating', 3))
    
    # Update flashcard using spaced repetition
    flashcards = data_manager.get_flashcards()
    if card_id in flashcards:
        card = flashcards[card_id]
        updated_card = SpacedRepetition.calculate_next_review(card, rating)
        data_manager.save_flashcard(updated_card)
    
    # Update session stats
    stats = session.get('flashcard_stats', {'correct': 0, 'total': 0})
    stats['total'] += 1
    if rating >= 3:
        stats['correct'] += 1
    session['flashcard_stats'] = stats
    
    # Move to next card
    session['current_flashcard'] = session.get('current_flashcard', 0) + 1
    
    return jsonify({'status': 'success'})

@app.route('/flashcard_session_complete')
@login_required
@subscription_required
def flashcard_session_complete():
    if 'flashcard_deck' not in session:
        return redirect(url_for('flashcards'))
    
    stats = session.get('flashcard_stats', {'correct': 0, 'total': 0})
    session_time = int(time.time() - session.get('flashcard_session_start', time.time()))
    
    # Update user study time
    user = get_current_user()
    user.total_study_time += session_time
    data_manager.save_user(user)
    
    # Clear session
    for key in ['flashcard_deck', 'current_flashcard', 'flashcard_session_start', 'flashcard_stats']:
        session.pop(key, None)
    
    template = BASE_TEMPLATE + """
    {% block title %}Session Complete - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card card-custom text-center">
                <div class="card-body">
                    <i class="fas fa-check-circle fa-4x text-success mb-3"></i>
                    <h3>Session Complete!</h3>
                    
                    <div class="row mt-4">
                        <div class="col-6">
                            <h4 class="text-primary">{{ stats.correct }}</h4>
                            <small class="text-muted">Known</small>
                        </div>
                        <div class="col-6">
                            <h4 class="text-info">{{ stats.total - stats.correct }}</h4>
                            <small class="text-muted">Learning</small>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <p class="text-muted">Study time: {{ "%.1f"|format(session_time / 60) }} minutes</p>
                    </div>
                    
                    <div class="mt-4">
                        <a href="{{ url_for('flashcards') }}" class="btn btn-custom me-2">
                            <i class="fas fa-redo me-2"></i>Study More
                        </a>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    return render_template_string(template, stats=stats, session_time=session_time)

# AI Tutor System
@app.route('/ai_tutor')
@login_required
@subscription_required
def ai_tutor():
    template = BASE_TEMPLATE + """
    {% block title %}AI Tutor - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row">
        <div class="col-md-8">
            <div class="card card-custom">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-robot text-primary me-2"></i>
                        CPP AI Tutor
                    </h5>
                </div>
                <div class="card-body">
                    <div id="chatMessages" style="height: 400px; overflow-y: auto; border: 1px solid #dee2e6; padding: 1rem; margin-bottom: 1rem; border-radius: 0.375rem;">
                        <div class="text-center text-muted">
                            <i class="fas fa-robot fa-2x mb-2"></i>
                            <p>Hello! I'm your CPP study assistant. Ask me anything about security concepts, study strategies, or exam preparation!</p>
                        </div>
                    </div>
                    
                    <form id="chatForm" onsubmit="sendMessage(event)">
                        <div class="input-group">
                            <input type="text" id="messageInput" class="form-control" 
                                   placeholder="Ask me anything about CPP..." required>
                            <button type="submit" class="btn btn-custom" id="sendButton">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card card-custom">
                <div class="card-header">
                    <h6 class="mb-0">Suggested Questions</h6>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('What are the key principles of physical security?')">
                            Physical Security Principles
                        </button>
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('Explain the difference between security clearance levels')">
                            Security Clearance Levels
                        </button>
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('What should I focus on for exam preparation?')">
                            Exam Preparation Tips
                        </button>
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('How does crisis management apply to security?')">
                            Crisis Management
                        </button>
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('What are common investigation techniques?')">
                            Investigation Techniques
                        </button>
                        <button class="btn btn-outline-primary btn-sm" onclick="askSuggested('Explain legal compliance in security operations')">
                            Legal Compliance
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="card card-custom mt-3">
                <div class="card-header">
                    <h6 class="mb-0">Study Tips</h6>
                </div>
                <div class="card-body">
                    <small class="text-muted">
                        <ul class="ps-3">
                            <li>Ask specific questions about concepts you don't understand</li>
                            <li>Request examples and case studies</li>
                            <li>Ask for study strategies for weak domains</li>
                            <li>Get clarification on confusing topics</li>
                            <li>Request practice scenarios</li>
                        </ul>
                    </small>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    
    {% block scripts %}
    <script>
        function sendMessage(event) {
            event.preventDefault();
            
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
            
            if (!message) return;
            
            addMessage('user', message);
            messageInput.value = '';
            
            // Show thinking indicator
            const thinkingId = 'thinking-' + Date.now();
            addMessage('assistant', '<i class="fas fa-spinner fa-spin"></i> Thinking...', thinkingId);
            
            // Send to AI
            fetch('{{ url_for("chat_with_ai") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: message})
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById(thinkingId).remove();
                addMessage('assistant', data.response);
            })
            .catch(error => {
                document.getElementById(thinkingId).remove();
                addMessage('assistant', 'Sorry, I encountered an error. Please try again.');
            });
        }
        
        function addMessage(sender, content, id = null) {
            const messagesDiv = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `mb-3 ${sender}`;
            if (id) messageDiv.id = id;
            
            messageDiv.innerHTML = `
                <div class="d-flex ${sender === 'user' ? 'justify-content-end' : ''}">
                    <div class="p-2 rounded ${sender === 'user' ? 'bg-primary text-white' : 'bg-light'}" 
                         style="max-width: 80%;">
                        ${content}
                    </div>
                </div>
            `;
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function askSuggested(question) {
            document.getElementById('messageInput').value = question;
            sendMessage(new Event('submit'));
        }
    </script>
    {% endblock %}
    """
    
    return render_template_string(template)

@app.route('/chat_with_ai', methods=['POST'])
@login_required
@subscription_required
@rate_limit(10, 60)  # 10 requests per minute
def chat_with_ai():
    data = request.get_json()
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Check if OpenAI API key is available
    if not app.config['OPENAI_API_KEY']:
        return jsonify({
            'response': "I'm sorry, but the AI tutor is currently unavailable. The OpenAI API key hasn't been configured. Please contact support or try again later."
        })
    
    try:
        # Prepare the system prompt
        system_prompt = """You are a helpful CPP (Certified Protection Professional) exam tutor. You specialize in:
        
        1. Physical Security (22% of exam)
        2. Personnel Security (15% of exam)  
        3. Information Systems Security (9% of exam)
        4. Crisis Management (11% of exam)
        5. Investigations (16% of exam)
        6. Legal and Regulatory (14% of exam)
        7. Professional and Ethical Responsibilities (13% of exam)
        
        Provide clear, accurate, and helpful responses about security concepts, exam strategies, and study tips. 
        Use examples when helpful and keep responses focused on CPP exam preparation."""
        
        # Make request to OpenAI
        headers = {
            'Authorization': f'Bearer {app.config["OPENAI_API_KEY"]}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': 'gpt-3.5-turbo',
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message}
            ],
            'max_tokens': 500,
            'temperature': 0.7
        }
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            ai_response = response.json()['choices'][0]['message']['content']
            return jsonify({'response': ai_response})
        else:
            logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
            return jsonify({
                'response': "I'm experiencing some technical difficulties. Please try again in a moment."
            })
            
    except requests.exceptions.Timeout:
        return jsonify({
            'response': "The request timed out. Please try again with a shorter question."
        })
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error in AI chat: {e}")
        return jsonify({
            'response': "I'm having trouble connecting to the AI service. Please try again later."
        })
    except Exception as e:
        logger.error(f"Unexpected error in AI chat: {e}")
        return jsonify({
            'response': "An unexpected error occurred. Please try again."
        })

# Billing System
@app.route('/billing')
@login_required
def billing():
    user = get_current_user()
    
    template = BASE_TEMPLATE + """
    {% block title %}Billing - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card card-custom">
                <div class="card-header">
                    <h4 class="mb-0">
                        <i class="fas fa-credit-card text-primary me-2"></i>
                        Subscription & Billing
                    </h4>
                </div>
                <div class="card-body">
                    {% if user.subscription_status == 'active' %}
                    <div class="alert alert-success">
                        <h5><i class="fas fa-check-circle me-2"></i>Active Subscription</h5>
                        <p>Your subscription is active and all features are available.</p>
                        <p><strong>Plan:</strong> {{ user.subscription_plan.title() }}</p>
                        {% if user.subscription_expires %}
                        <p><strong>Expires:</strong> {{ user.subscription_expires[:10] }}</p>
                        {% endif %}
                    </div>
                    
                    <div class="text-center">
                        <a href="{{ url_for('customer_portal') }}" class="btn btn-outline-primary">
                            <i class="fas fa-cog me-2"></i>Manage Subscription
                        </a>
                    </div>
                    {% else %}
                    <div class="alert alert-warning">
                        <h5><i class="fas fa-exclamation-triangle me-2"></i>Subscription Required</h5>
                        <p>Access to study materials requires an active subscription. Choose a plan below to get started!</p>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <div class="card border-primary">
                                <div class="card-header bg-primary text-white text-center">
                                    <h5 class="mb-0">Monthly Plan</h5>
                                </div>
                                <div class="card-body text-center">
                                    <h2 class="text-primary">$29.99</h2>
                                    <p class="text-muted">per month</p>
                                    <ul class="list-unstyled">
                                        <li><i class="fas fa-check text-success me-2"></i>Full question bank (500+ questions)</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Interactive flashcards</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Mock exams</li>
                                        <li><i class="fas fa-check text-success me-2"></i>AI tutor access</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Progress tracking</li>
                                    </ul>
                                    <button class="btn btn-primary w-100" onclick="subscribe('monthly')">
                                        Subscribe Monthly
                                    </button>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6 mb-3">
                            <div class="card border-success">
                                <div class="card-header bg-success text-white text-center">
                                    <h5 class="mb-0">6-Month Plan</h5>
                                    <small class="badge bg-light text-success">Save 17%!</small>
                                </div>
                                <div class="card-body text-center">
                                    <h2 class="text-success">$149.99</h2>
                                    <p class="text-muted">for 6 months</p>
                                    <p class="small text-success"><strong>Save $30!</strong> vs monthly</p>
                                    <ul class="list-unstyled">
                                        <li><i class="fas fa-check text-success me-2"></i>Full question bank (500+ questions)</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Interactive flashcards</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Mock exams</li>
                                        <li><i class="fas fa-check text-success me-2"></i>AI tutor access</li>
                                        <li><i class="fas fa-check text-success me-2"></i>Progress tracking</li>
                                    </ul>
                                    <button class="btn btn-success w-100" onclick="subscribe('6month')">
                                        Subscribe 6-Month
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <!-- Stripe Checkout Form -->
    <form id="checkout-form" style="display: none;">
        <div id="card-element"></div>
        <button id="submit-button">Subscribe</button>
    </form>
    {% endblock %}
    
    {% block scripts %}
    <script>
        const stripe = Stripe('{{ stripe_key }}');
        let currentPlan = null;
        
        function subscribe(plan) {
            currentPlan = plan;
            
            // In a real implementation, you would:
            // 1. Create a Stripe checkout session
            // 2. Redirect to Stripe checkout
            // 3. Handle webhooks for subscription creation
            
            // For demo purposes, we'll simulate successful subscription
            fetch('{{ url_for("simulate_subscription") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({plan: plan})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    alert('Subscription failed. Please try again.');
                }
            });
        }
    </script>
    {% endblock %}
    """
    
    stripe_key = app.config.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_demo')
    return render_template_string(template, user=user, stripe_key=stripe_key)

@app.route('/simulate_subscription', methods=['POST'])
@login_required
def simulate_subscription():
    """Simulate subscription for demo purposes"""
    data = request.get_json()
    plan = data.get('plan', 'monthly')
    
    user = get_current_user()
    user.subscription_status = 'active'
    user.subscription_plan = plan
    
    # Set expiration date
    if plan == 'monthly':
        expires = dt.now() + timedelta(days=30)
    else:  # 6month
        expires = dt.now() + timedelta(days=180)
    
    user.subscription_expires = expires.isoformat()
    data_manager.save_user(user)
    
    return jsonify({'success': True})

@app.route('/customer_portal')
@login_required
def customer_portal():
    # In a real implementation, this would redirect to Stripe customer portal
    flash('Customer portal would redirect to Stripe management interface', 'info')
    return redirect(url_for('billing'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    template = BASE_TEMPLATE + """
    {% block title %}Page Not Found - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="text-center">
        <i class="fas fa-search fa-4x text-muted mb-4"></i>
        <h1>404 - Page Not Found</h1>
        <p class="text-muted">The page you're looking for doesn't exist.</p>
        <a href="{{ url_for('dashboard') }}" class="btn btn-custom">
            <i class="fas fa-home me-2"></i>Go to Dashboard
        </a>
    </div>
    {% endblock %}
    """
    return render_template_string(template), 404

@app.errorhandler(500)
def internal_error(error):
    template = BASE_TEMPLATE + """
    {% block title %}Server Error - CPP Test Prep{% endblock %}
    {% block content %}
    <div class="text-center">
        <i class="fas fa-exclamation-triangle fa-4x text-warning mb-4"></i>
        <h1>500 - Server Error</h1>
        <p class="text-muted">Something went wrong on our end. Please try again later.</p>
        <a href="{{ url_for('dashboard') }}" class="btn btn-custom">
            <i class="fas fa-home me-2"></i>Go to Dashboard
        </a>
    </div>
    {% endblock %}
    """
    return render_template_string(template), 500

# Application Startup
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info(f"Starting CPP Test Prep Platform on port {port}")
    logger.info(f"Debug mode: {debug}")
    logger.info(f"Data directory: {app.config['DATA_DIR']}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)


