// Load environment variables
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const https = require('https');
const fs = require('fs');
const { storage } = require('./storage');

const app = express();
const PORT = parseInt(process.env.PORT) || 3000;
const MAX_SECRET_LENGTH = parseInt(process.env.MAX_SECRET_LENGTH) || 50000;

// Password generator configuration
const DEFAULT_SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const PASSWORD_EXCLUDE_CHARS = process.env.PASSWORD_EXCLUDE_CHARS || '';
const PASSWORD_SPECIAL_CHARS = process.env.PASSWORD_SPECIAL_CHARS || DEFAULT_SPECIAL_CHARS;
const PASSPHRASE_SEPARATOR = process.env.PASSPHRASE_SEPARATOR || '-';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcElem: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : true,
  credentials: false
}));

// Trust proxy for Vercel (needed for express-rate-limit)
app.set('trust proxy', true);

app.use(express.json({ limit: '10mb' }));

// Explicitly serve crypto-utils.js with correct MIME type
app.get('/crypto-utils.js', (req, res) => {
  res.setHeader('Content-Type', 'text/javascript');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'crypto-utils.js'));
});

app.use(express.static('public'));

const createLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.CREATE_RATE_LIMIT) || 10, // limit each IP to 10 requests per windowMs
  message: { error: 'Too many secrets created, try again later' }
});

const retrieveLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.RETRIEVE_RATE_LIMIT) || 50, // limit each IP to 50 requests per windowMs
  message: { error: 'Too many retrieval attempts, try again later' }
});

// Storage is now handled by the storage manager

// Security: Input sanitization functions
function sanitizeString(input, maxLength = 1000) {
  if (typeof input !== 'string') return '';
  
  return input
    .slice(0, maxLength) // Limit length
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
    .trim();
}

function validateSecretContent(content) {
  if (!content || typeof content !== 'string') {
    return { valid: false, error: 'Invalid content' };
  }
  
  // Check for suspicious patterns that might indicate XSS attempts
  const suspiciousPatterns = [
    /<script[^>]*>/i,
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
    /on\w+\s*=/i,
    /<iframe[^>]*>/i,
    /<object[^>]*>/i,
    /<embed[^>]*>/i
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(content)) {
      return { valid: false, error: 'Content contains potentially unsafe elements' };
    }
  }
  
  return { valid: true };
}

function validateAndSanitizeGeneratorInput(type, length, wordCount, separator) {
  const result = { valid: true, sanitized: {} };
  
  // Validate type
  if (!type || (type !== 'password' && type !== 'passphrase')) {
    return { valid: false, error: 'Invalid generation type' };
  }
  
  result.sanitized.type = type;
  
  if (type === 'password') {
    const len = parseInt(length);
    if (isNaN(len) || len < 4 || len > 128) {
      return { valid: false, error: 'Invalid password length' };
    }
    result.sanitized.length = len;
  } else {
    const words = parseInt(wordCount) || 4;
    if (isNaN(words) || words < 2 || words > 10) {
      return { valid: false, error: 'Invalid word count' };
    }
    
    // Sanitize separator
    let sep = separator || '-';
    if (typeof sep !== 'string') sep = '-';
    sep = sanitizeString(sep, 10);
    
    // Only allow safe separator characters
    if (!/^[._\-#@$%&*+=|~`^!?\s]*$/.test(sep)) {
      sep = '-';
    }
    
    result.sanitized.wordCount = words;
    result.sanitized.separator = sep;
  }
  
  return result;
}

function generateSecureId() {
  return crypto.randomBytes(32).toString('base64url');
}

// Password generator functions with cryptographic security
function generatePassword(length = 16) {
// Ensure minimum length for complexity requirements
  if (length < 4) {
    throw new Error('Password length must be at least 4 characters to meet complexity requirements');
  }

  // Define standard character categories
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const special = PASSWORD_SPECIAL_CHARS;

  // Apply exclusions to each category
  function filterCategory(category) {
    if (!PASSWORD_EXCLUDE_CHARS) return category;
    let filtered = category;
    for (const char of PASSWORD_EXCLUDE_CHARS) {
      filtered = filtered.replace(new RegExp(`\\${char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'), '');
    }
    return filtered;
  }
  
  const availableUppercase = filterCategory(uppercase);
  const availableLowercase = filterCategory(lowercase);
  const availableDigits = filterCategory(digits);
  const availableSpecial = filterCategory(special);
  
  // Build final character pool from filtered categories
  const availableChars = availableUppercase + availableLowercase + availableDigits + availableSpecial;
  
  // Ensure we have at least one character from each required category
  if (availableUppercase.length === 0 || availableLowercase.length === 0 || 
      availableDigits.length === 0 || availableSpecial.length === 0) {
    throw new Error('Cannot meet complexity requirements: missing required character types after exclusions');
  }
  
  if (availableChars.length < 10) {
    throw new Error('Character set too small for secure password generation (minimum 10 characters)');
  }
  
  // Start with one character from each required category
  let password = '';
  password += availableUppercase[crypto.randomInt(0, availableUppercase.length)];
  password += availableLowercase[crypto.randomInt(0, availableLowercase.length)];
  password += availableDigits[crypto.randomInt(0, availableDigits.length)];
  password += availableSpecial[crypto.randomInt(0, availableSpecial.length)];
  
  // Fill remaining positions with random characters from full available set
  for (let i = 4; i < length; i++) {
    const randomIndex = crypto.randomInt(0, availableChars.length);
    password += availableChars[randomIndex];
  }
  
  // Shuffle the password to randomize character positions
  const passwordArray = password.split('');
  for (let i = passwordArray.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
  }
  password = passwordArray.join('');
  
  // Verify password has reasonable entropy
  const uniqueChars = new Set(password).size;
  if (uniqueChars < Math.min(length / 3, 4)) {
    // Regenerate if entropy is too low (recursive with max attempts)
    if (length > 4 && uniqueChars < 3) {
      return generatePassword(length); // Retry once for better entropy
    }
  }
  
  return password;
}

function generatePassphrase(wordCount = 4, separator = null) {
  // EFF Large Wordlist subset - cryptographically secure word list with varied lengths
  const words = [
    'abacus', 'abdomen', 'abdominal', 'abide', 'abiding', 'ability', 'ablaze', 'able', 'abnormal', 'aboard',
    'aboriginal', 'abort', 'about', 'above', 'absence', 'absent', 'absolute', 'abstract', 'absurd', 'accent',
    'accept', 'acceptance', 'accepted', 'accepting', 'access', 'accident', 'accompany', 'accomplish', 'accord', 'account',
    'accuracy', 'accurate', 'accusation', 'accuse', 'achieve', 'achievement', 'acid', 'acidic', 'acknowledge', 'acquire',
    'across', 'action', 'activate', 'active', 'activist', 'activity', 'actor', 'actress', 'actual', 'acute',
    'adamant', 'adapt', 'add', 'addition', 'additional', 'address', 'adequate', 'adjust', 'adjustment', 'admin',
    'administration', 'administrative', 'administrator', 'admire', 'admission', 'admit', 'adolescent', 'adopt', 'adult', 'advance',
    'advanced', 'advantage', 'adventure', 'adverse', 'advertise', 'advice', 'advise', 'advisor', 'advocacy', 'advocate',
    'aerial', 'aerobic', 'aerospace', 'affair', 'affect', 'affiliate', 'affirm', 'afford', 'afraid', 'african',
    'after', 'afternoon', 'afterward', 'again', 'against', 'age', 'aged', 'agency', 'agenda', 'agent',
    'aggressive', 'aging', 'agnostic', 'ago', 'agree', 'agreement', 'agricultural', 'agriculture', 'ahead', 'aid',
    'aim', 'air', 'aircraft', 'airline', 'airplane', 'airport', 'aisle', 'alarm', 'album', 'alcohol',
    'alert', 'alien', 'align', 'alike', 'alive', 'all', 'alliance', 'allow', 'almost', 'alone',
    'along', 'already', 'also', 'alter', 'alternative', 'although', 'aluminum', 'always', 'amazing', 'ambassador',
    'amber', 'ambition', 'ambulance', 'american', 'among', 'amount', 'analysis', 'analyst', 'analyze', 'ancestor',
    'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal', 'anniversary', 'announce', 'annual', 'another',
    'answer', 'anticipate', 'anxiety', 'anxious', 'anybody', 'anymore', 'anyone', 'anything', 'anyway', 'anywhere',
    'apart', 'apartment', 'apparent', 'apparently', 'appeal', 'appear', 'appearance', 'apple', 'application', 'apply',
    'appoint', 'appointment', 'appreciate', 'approach', 'appropriate', 'approval', 'approve', 'approximate', 'architect', 'area',
    'argue', 'argument', 'arise', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
    'arrival', 'arrive', 'arrow', 'art', 'article', 'artist', 'artistic', 'as', 'ash', 'asian',
    'aside', 'ask', 'asleep', 'aspect', 'assault', 'assert', 'assess', 'assessment', 'asset', 'assign',
    'assist', 'assistance', 'assistant', 'associate', 'association', 'assume', 'assumption', 'assure', 'athlete', 'athletic',
    'atmosphere', 'attach', 'attack', 'attempt', 'attend', 'attention', 'attitude', 'attorney', 'attract', 'attractive',
    'attribute', 'audience', 'audio', 'audit', 'august', 'author', 'authority', 'auto', 'available', 'average',
    'avoid', 'award', 'aware', 'awareness', 'away', 'awesome', 'awful', 'awkward', 'axis', 'baby',
    'bachelor', 'back', 'background', 'backup', 'backward', 'bacon', 'bacteria', 'bad', 'badge', 'badly',
    'bag', 'balance', 'ball', 'ban', 'banana', 'band', 'bang', 'bank', 'bar', 'bare',
    'barely', 'bargain', 'barrel', 'barrier', 'base', 'baseball', 'basic', 'basis', 'basket', 'basketball',
    'bathroom', 'battery', 'battle', 'beach', 'bean', 'bear', 'bearing', 'beast', 'beat', 'beautiful',
    'beauty', 'because', 'become', 'bed', 'bedroom', 'bee', 'beef', 'beer', 'before', 'begin',
    'beginning', 'behavior', 'behind', 'being', 'belief', 'believe', 'bell', 'belong', 'below', 'belt',
    'bench', 'bend', 'beneath', 'benefit', 'beside', 'best', 'bet', 'better', 'between', 'beyond',
    'bicycle', 'bid', 'big', 'bike', 'bill', 'billion', 'bind', 'biological', 'biology', 'bird',
    'birth', 'birthday', 'bit', 'bite', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blind',
    'block', 'blog', 'blood', 'blow', 'blue', 'board', 'boat', 'body', 'bold', 'bomb',
    'bond', 'bone', 'bonus', 'book', 'boom', 'boost', 'boot', 'border', 'born', 'borrow',
    'boss', 'both', 'bother', 'bottle', 'bottom', 'boundary', 'bowl', 'box', 'boy', 'bracket',
    'brain', 'branch', 'brand', 'brass', 'brave', 'bread', 'break', 'breakfast', 'breast', 'breath',
    'breathe', 'brick', 'bridge', 'brief', 'briefly', 'bright', 'brilliant', 'bring', 'broad', 'broken',
    'brother', 'brown', 'brush', 'buck', 'budget', 'build', 'building', 'bullet', 'bunch', 'bundle',
    'burden', 'bureau', 'burn', 'bury', 'bus', 'business', 'busy', 'but', 'butter', 'button',
    'buy', 'buyer', 'buying', 'buzz', 'by', 'cabin', 'cabinet', 'cable', 'cake', 'calculate',
    'call', 'calm', 'camera', 'camp', 'campaign', 'campus', 'can', 'cancer', 'candidate', 'candle',
    'candy', 'cannon', 'cannot', 'canoe', 'canvas', 'cap', 'capability', 'capable', 'capacity', 'capital',
    'captain', 'capture', 'car', 'carbon', 'card', 'care', 'career', 'careful', 'carefully', 'cargo',
    'carry', 'case', 'cash', 'cast', 'casual', 'cat', 'catch', 'category', 'cathedral', 'cattle',
    'cause', 'cave', 'ceiling', 'celebrate', 'celebration', 'celebrity', 'cell', 'center', 'central', 'century',
    'ceremony', 'certain', 'certainly', 'chain', 'chair', 'chairman', 'challenge', 'chamber', 'champion', 'championship',
    'chance', 'change', 'changing', 'channel', 'chaos', 'chapter', 'character', 'characteristic', 'characterize', 'charge',
    'charity', 'charm', 'chart', 'chase', 'cheap', 'check', 'cheese', 'chemical', 'chemistry', 'chest',
    'chicken', 'chief', 'child', 'childhood', 'chip', 'chocolate', 'choice', 'choose', 'church', 'circle',
    'circumstance', 'cite', 'citizen', 'city', 'civil', 'civilian', 'claim', 'class', 'classic', 'classroom',
    'clean', 'clear', 'clearly', 'client', 'cliff', 'climate', 'climb', 'clock', 'close', 'closely',
    'closer', 'clothes', 'cloud', 'club', 'clue', 'cluster', 'coach', 'coal', 'coast', 'coat',
    'code', 'coffee', 'cognitive', 'cold', 'collapse', 'colleague', 'collect', 'collection', 'collective', 'college',
    'colonial', 'color', 'column', 'combination', 'combine', 'come', 'comedy', 'comfort', 'comfortable', 'command',
    'comment', 'commercial', 'commission', 'commit', 'commitment', 'committee', 'common', 'communicate', 'communication', 'community',
    'company', 'compare', 'comparison', 'compete', 'competition', 'competitive', 'competitor', 'complain', 'complaint', 'complete',
    'completely', 'complex', 'complexity', 'compliance', 'complicate', 'complicated', 'component', 'compose', 'composition', 'comprehensive',
    'computer', 'concentrate', 'concentration', 'concept', 'concern', 'concerned', 'concerning', 'concert', 'conclude', 'conclusion',
    'concrete', 'condition', 'conduct', 'conference', 'confidence', 'confident', 'confirm', 'conflict', 'confront', 'confusion',
    'congress', 'connect', 'connection', 'consciousness', 'consensus', 'consent', 'consequence', 'conservative', 'consider', 'considerable',
    'consideration', 'consist', 'consistent', 'constant', 'constitute', 'constitution', 'construct', 'construction', 'consume', 'consumer',
    'consumption', 'contact', 'contain', 'container', 'contemporary', 'content', 'contest', 'context', 'continent', 'continue',
    'continued', 'contract', 'contrast', 'contribute', 'contribution', 'control', 'controversial', 'controversy', 'convention', 'conventional',
    'conversation', 'convert', 'conviction', 'convince', 'cook', 'cookie', 'cooking', 'cool', 'cooperation', 'cope',
    'copy', 'core', 'corn', 'corner', 'corporate', 'corporation', 'correct', 'correspondent', 'cost', 'cotton',
    'couch', 'could', 'council', 'count', 'counter', 'country', 'county', 'couple', 'courage', 'course',
    'court', 'courtesy', 'cover', 'coverage', 'cow', 'crack', 'craft', 'crash', 'crazy', 'cream',
    'create', 'creation', 'creative', 'creativity', 'creator', 'creature', 'credit', 'crew', 'crime', 'criminal',
    'crisis', 'criteria', 'critic', 'critical', 'criticism', 'criticize', 'crop', 'cross', 'crowd', 'crucial',
    'cruise', 'cry', 'crystal', 'cultural', 'culture', 'cup', 'curious', 'current', 'currently', 'curriculum',
    'curve', 'custom', 'customer', 'cut', 'cycle', 'dad', 'daily', 'damage', 'dance', 'danger',
    'dangerous', 'dare', 'dark', 'darkness', 'data', 'database', 'date', 'daughter', 'day', 'dead',
    'deadline', 'deal', 'dealer', 'dealing', 'dear', 'death', 'debate', 'debt', 'decade', 'decide',
    'decision', 'deck', 'declare', 'decline', 'decrease', 'deep', 'deeply', 'deer', 'defeat', 'defend',
    'defense', 'defensive', 'deficit', 'define', 'definitely', 'definition', 'degree', 'deliver', 'delivery', 'demand',
    'democracy', 'democratic', 'demonstrate', 'demonstration', 'department', 'depend', 'dependent', 'depending', 'depict', 'depression',
    'depth', 'deputy', 'derive', 'describe', 'description', 'desert', 'deserve', 'design', 'designer', 'desire',
    'desk', 'desperate', 'despite', 'destroy', 'destruction', 'detail', 'detailed', 'detect', 'determine', 'develop',
    'development', 'device', 'devote', 'dialogue', 'diamond', 'diary', 'die', 'diet', 'differ', 'difference',
    'different', 'differently', 'difficult', 'difficulty', 'digital', 'dimension', 'dining', 'dinner', 'direct', 'direction',
    'directly', 'director', 'dirt', 'dirty', 'disability', 'disagree', 'disappear', 'disaster', 'discipline', 'discourse',
    'discover', 'discovery', 'discrimination', 'discuss', 'discussion', 'disease', 'dish', 'dismiss', 'disorder', 'display',
    'disposal', 'dispose', 'dispute', 'distance', 'distant', 'distinct', 'distinction', 'distinguish', 'distribute', 'distribution',
    'district', 'diverse', 'diversity', 'divide', 'division', 'divorce', 'doctor', 'document', 'dog', 'domain',
    'domestic', 'dominant', 'dominate', 'door', 'double', 'doubt', 'down', 'downtown', 'dozen', 'draft',
    'drag', 'drama', 'dramatic', 'dramatically', 'draw', 'drawing', 'dream', 'dress', 'drink', 'drive',
    'driver', 'drop', 'drug', 'dry', 'due', 'during', 'dust', 'duty', 'each', 'eager',
    'ear', 'early', 'earn', 'earnings', 'earth', 'earthquake', 'ease', 'easily', 'east', 'eastern',
    'easy', 'eat', 'economic', 'economics', 'economist', 'economy', 'edge', 'edition', 'editor', 'education',
    'educational', 'educator', 'effect', 'effective', 'effectively', 'efficiency', 'efficient', 'effort', 'eight', 'either',
    'elderly', 'elect', 'election', 'electric', 'electricity', 'electronic', 'element', 'elementary', 'eliminate', 'elite',
    'else', 'elsewhere', 'emerge', 'emergency', 'emission', 'emotion', 'emotional', 'emphasis', 'emphasize', 'employ',
    'employee', 'employer', 'employment', 'empty', 'enable', 'encounter', 'encourage', 'end', 'enemy', 'energy',
    'enforcement', 'engage', 'engine', 'engineer', 'engineering', 'english', 'enhance', 'enjoy', 'enormous', 'enough',
    'ensure', 'enter', 'enterprise', 'entertainment', 'entire', 'entirely', 'entity', 'entrance', 'entry', 'environment',
    'environmental', 'episode', 'equal', 'equally', 'equipment', 'equivalent', 'era', 'error', 'escape', 'especially',
    'essay', 'essential', 'essentially', 'establish', 'establishment', 'estate', 'estimate', 'ethics', 'ethnic', 'european',
    'evaluate', 'evaluation', 'even', 'evening', 'event', 'eventually', 'ever', 'every', 'everybody', 'everyday',
    'everyone', 'everything', 'everywhere', 'evidence', 'evident', 'evil', 'evolution', 'evolve', 'exact', 'exactly',
    'exam', 'examination', 'examine', 'example', 'exceed', 'excellent', 'except', 'exception', 'exchange', 'excited',
    'excitement', 'exciting', 'exclude', 'excuse', 'executive', 'exercise', 'exhibit', 'exhibition', 'exist', 'existence',
    'existing', 'exit', 'expand', 'expansion', 'expect', 'expectation', 'expected', 'expense', 'expensive', 'experience',
    'experiment', 'expert', 'explain', 'explanation', 'explore', 'explosion', 'expose', 'exposure', 'express', 'expression',
    'extend', 'extension', 'extensive', 'extent', 'external', 'extra', 'extraordinary', 'extreme', 'extremely', 'eye',
    'fabric', 'face', 'facility', 'fact', 'factor', 'factory', 'faculty', 'fade', 'fail', 'failure',
    'fair', 'fairly', 'faith', 'fall', 'false', 'familiar', 'family', 'famous', 'fan', 'fantasy',
    'far', 'farm', 'farmer', 'fashion', 'fast', 'fat', 'fate', 'father', 'fault', 'favor',
    'favorite', 'fear', 'feature', 'federal', 'fee', 'feed', 'feel', 'feeling', 'fellow', 'female',
    'fence', 'few', 'fiber', 'fiction', 'field', 'fifteen', 'fifth', 'fifty', 'fight', 'figure',
    'file', 'fill', 'film', 'final', 'finally', 'finance', 'financial', 'find', 'finding', 'fine',
    'finger', 'finish', 'fire', 'firm', 'first', 'fish', 'fishing', 'fit', 'fitness', 'five',
    'fix', 'flag', 'flame', 'flat', 'flavor', 'flee', 'flesh', 'flight', 'float', 'floor',
    'flow', 'flower', 'fly', 'focus', 'folk', 'follow', 'following', 'food', 'foot', 'football',
    'for', 'force', 'foreign', 'forest', 'forever', 'forget', 'form', 'formal', 'formation', 'former',
    'formula', 'forth', 'fortune', 'forum', 'forward', 'foundation', 'founder', 'four', 'fourth', 'frame',
    'framework', 'free', 'freedom', 'freeze', 'french', 'frequency', 'frequent', 'frequently', 'fresh', 'friend',
    'friendly', 'friendship', 'from', 'front', 'fruit', 'frustration', 'fuel', 'full', 'fully', 'fun',
    'function', 'fund', 'fundamental', 'funding', 'funeral', 'funny', 'furniture', 'furthermore', 'future', 'gain',
    'galaxy', 'gallery', 'game', 'gang', 'gap', 'garage', 'garden', 'garlic', 'gas', 'gate',
    'gather', 'gay', 'gaze', 'gear', 'gender', 'gene', 'general', 'generally', 'generate', 'generation',
    'generator', 'genetic', 'gentleman', 'gently', 'get', 'ghost', 'giant', 'gift', 'girl', 'girlfriend',
    'give', 'given', 'giving', 'glad', 'glance', 'glass', 'global', 'glove', 'go', 'goal',
    'god', 'gold', 'golden', 'golf', 'good', 'government', 'governor', 'grab', 'grade', 'gradually',
    'graduate', 'grain', 'grand', 'grant', 'grass', 'grave', 'gray', 'great', 'greatest', 'green',
    'grocery', 'ground', 'group', 'grow', 'growing', 'growth', 'guarantee', 'guard', 'guess', 'guest',
    'guide', 'guideline', 'guilty', 'gun', 'guy', 'habit', 'habitat', 'hair', 'half', 'hall',
    'hand', 'handful', 'handle', 'hang', 'happen', 'happy', 'hard', 'hardly', 'harm', 'hat',
    'hate', 'have', 'he', 'head', 'headline', 'headquarters', 'health', 'healthy', 'hear', 'hearing',
    'heart', 'heat', 'heaven', 'heavily', 'heavy', 'heel', 'height', 'help', 'helpful', 'her',
    'here', 'heritage', 'hero', 'herself', 'hey', 'hide', 'high', 'highlight', 'highly', 'highway',
    'hill', 'him', 'himself', 'hip', 'hire', 'his', 'historian', 'historic', 'historical', 'history',
    'hit', 'hold', 'hole', 'holiday', 'holy', 'home', 'homeless', 'honest', 'honey', 'honor',
    'hope', 'horizon', 'horror', 'horse', 'hospital', 'host', 'hot', 'hotel', 'hour', 'house',
    'household', 'housing', 'how', 'however', 'huge', 'human', 'hundred', 'hungry', 'hunt', 'hunter',
    'hunting', 'hurt', 'husband', 'hypothesis', 'ice', 'idea', 'ideal', 'identification', 'identify', 'identity',
    'ideology', 'if', 'ignore', 'ill', 'illegal', 'illness', 'illustrate', 'image', 'imagination', 'imagine',
    'immediate', 'immediately', 'immigrant', 'immigration', 'impact', 'implement', 'implication', 'imply', 'importance', 'important',
    'impose', 'impossible', 'impress', 'impression', 'impressive', 'improve', 'improvement', 'in', 'incentive', 'incident',
    'include', 'including', 'income', 'incorporate', 'increase', 'increased', 'increasing', 'increasingly', 'incredible', 'indeed',
    'independence', 'independent', 'index', 'indian', 'indicate', 'indication', 'individual', 'industrial', 'industry', 'infant',
    'infection', 'inflation', 'influence', 'inform', 'information', 'ingredient', 'initial', 'initially', 'initiative', 'injury',
    'inner', 'innocent', 'innovation', 'input', 'inquiry', 'inside', 'insight', 'insist', 'inspection', 'inspector',
    'inspiration', 'install', 'instance', 'instant', 'instead', 'institution', 'institutional', 'instruction', 'instructor', 'instrument',
    'insurance', 'intellectual', 'intelligence', 'intelligent', 'intend', 'intense', 'intensity', 'intention', 'interaction', 'interest',
    'interested', 'interesting', 'internal', 'international', 'internet', 'interpretation', 'interview', 'into', 'introduce', 'introduction',
    'invasion', 'invest', 'investigate', 'investigation', 'investigator', 'investment', 'investor', 'invite', 'involve', 'involved',
    'involvement', 'iron', 'islamic', 'island', 'israeli', 'issue', 'it', 'italian', 'item', 'its',
    'itself', 'jacket', 'jail', 'japanese', 'jet', 'jewish', 'job', 'join', 'joint', 'joke',
    'journal', 'journalist', 'journey', 'joy', 'judge', 'judgment', 'juice', 'jump', 'junior', 'jury',
    'just', 'justice', 'justify', 'keep', 'key', 'kick', 'kid', 'kill', 'killer', 'killing',
    'kind', 'king', 'kiss', 'kitchen', 'knee', 'knife', 'knock', 'know', 'knowledge', 'known',
    'lab', 'label', 'labor', 'laboratory', 'lack', 'lady', 'lake', 'land', 'landscape', 'language',
    'lap', 'large', 'largely', 'last', 'late', 'later', 'latter', 'laugh', 'launch', 'law',
    'lawn', 'lawsuit', 'lawyer', 'lay', 'layer', 'lead', 'leader', 'leadership', 'leading', 'leaf',
    'league', 'lean', 'learn', 'learning', 'least', 'leather', 'leave', 'left', 'leg', 'legacy',
    'legal', 'legend', 'legislation', 'legitimate', 'lemon', 'length', 'less', 'lesson', 'let', 'letter',
    'level', 'liability', 'liberal', 'library', 'license', 'lie', 'life', 'lifestyle', 'lifetime', 'lift',
    'light', 'like', 'likely', 'limit', 'limitation', 'limited', 'line', 'link', 'lip', 'list',
    'listen', 'literally', 'literary', 'literature', 'little', 'live', 'living', 'loan', 'local', 'locate',
    'location', 'lock', 'long', 'longer', 'look', 'loose', 'lose', 'loss', 'lost', 'lot',
    'lots', 'loud', 'love', 'lovely', 'lover', 'low', 'lower', 'luck', 'lucky', 'lunch',
    'machine', 'mad', 'magazine', 'magic', 'mail', 'main', 'mainly', 'maintain', 'maintenance', 'major',
    'majority', 'make', 'maker', 'makeup', 'making', 'male', 'mall', 'man', 'manage', 'management',
    'manager', 'manner', 'manufacturer', 'manufacturing', 'many', 'map', 'margin', 'mark', 'market', 'marketing',
    'marriage', 'married', 'marry', 'mask', 'mass', 'massive', 'master', 'match', 'material', 'math',
    'matter', 'may', 'maybe', 'mayor', 'me', 'meal', 'mean', 'meaning', 'meanwhile', 'measure',
    'measurement', 'meat', 'mechanism', 'media', 'medical', 'medicine', 'medium', 'meet', 'meeting', 'member',
    'membership', 'memory', 'mental', 'mention', 'menu', 'mere', 'merely', 'mess', 'message', 'metal',
    'method', 'middle', 'might', 'military', 'milk', 'mind', 'mine', 'minister', 'minor', 'minority',
    'minute', 'miracle', 'mirror', 'miss', 'missile', 'missing', 'mission', 'mistake', 'mix', 'mixture',
    'mode', 'model', 'moderate', 'modern', 'modest', 'mom', 'moment', 'money', 'monitor', 'month',
    'mood', 'moon', 'moral', 'more', 'moreover', 'morning', 'mortgage', 'most', 'mostly', 'mother',
    'motion', 'motivation', 'motor', 'mount', 'mountain', 'mouse', 'mouth', 'move', 'movement', 'movie',
    'much', 'multiple', 'murder', 'muscle', 'museum', 'music', 'musical', 'musician', 'muslim', 'must',
    'mutual', 'my', 'myself', 'mystery', 'myth', 'naked', 'name', 'narrative', 'narrow', 'nation',
    'national', 'native', 'natural', 'naturally', 'nature', 'navy', 'near', 'nearby', 'nearly', 'necessarily',
    'necessary', 'neck', 'need', 'negative', 'negotiate', 'negotiation', 'neighbor', 'neighborhood', 'neither', 'nerve',
    'net', 'network', 'never', 'nevertheless', 'new', 'newly', 'news', 'newspaper', 'next', 'nice',
    'night', 'nine', 'no', 'nobody', 'nod', 'noise', 'nomination', 'none', 'nonetheless', 'noon',
    'nor', 'normal', 'normally', 'north', 'northern', 'nose', 'not', 'note', 'nothing', 'notice',
    'notion', 'novel', 'now', 'nowhere', 'nuclear', 'number', 'numerous', 'nurse', 'nut', 'object',
    'objective', 'obligation', 'observation', 'observe', 'observer', 'obtain', 'obvious', 'obviously', 'occasion', 'occasionally',
    'occupation', 'occupy', 'occur', 'ocean', 'odd', 'of', 'off', 'offense', 'offensive', 'offer',
    'office', 'officer', 'official', 'often', 'oh', 'oil', 'ok', 'okay', 'old', 'olympic',
    'on', 'once', 'one', 'ongoing', 'onion', 'online', 'only', 'onto', 'open', 'opening',
    'operate', 'operating', 'operation', 'operator', 'opinion', 'opponent', 'opportunity', 'oppose', 'opposite', 'opposition',
    'option', 'or', 'orange', 'order', 'ordinary', 'organic', 'organization', 'organizational', 'organize', 'orientation',
    'origin', 'original', 'originally', 'other', 'others', 'otherwise', 'ought', 'our', 'ourselves', 'out',
    'outcome', 'outside', 'overall', 'overcome', 'overlook', 'owe', 'own', 'owner', 'pace', 'pack',
    'package', 'page', 'pain', 'painful', 'paint', 'painter', 'painting', 'pair', 'pale', 'palm',
    'pan', 'panel', 'paper', 'parent', 'park', 'parking', 'part', 'participant', 'participate', 'participation',
    'particular', 'particularly', 'partly', 'partner', 'partnership', 'party', 'pass', 'passage', 'passenger', 'passion',
    'past', 'pat', 'patch', 'path', 'patient', 'pattern', 'pause', 'pay', 'payment', 'peace',
    'peak', 'peer', 'penalty', 'people', 'pepper', 'per', 'perceive', 'percentage', 'perception', 'perfect',
    'perform', 'performance', 'performer', 'perhaps', 'period', 'permanent', 'permission', 'permit', 'person', 'personal',
    'personality', 'personally', 'personnel', 'perspective', 'persuade', 'pet', 'phase', 'phenomenon', 'philosophy', 'phone',
    'photo', 'photograph', 'photographer', 'photography', 'phrase', 'physical', 'physically', 'physician', 'piano', 'pick',
    'picture', 'piece', 'pile', 'pilot', 'pine', 'pink', 'pipe', 'pitch', 'place', 'plan',
    'plane', 'planet', 'planning', 'plant', 'plastic', 'plate', 'platform', 'play', 'player', 'please',
    'pleasure', 'plenty', 'plot', 'plus', 'pocket', 'poem', 'poet', 'poetry', 'point', 'pole',
    'police', 'policy', 'political', 'politically', 'politician', 'politics', 'poll', 'pollution', 'pool', 'poor',
    'pop', 'popular', 'popularity', 'population', 'pork', 'port', 'portion', 'portrait', 'portray', 'pose',
    'position', 'positive', 'possess', 'possession', 'possibility', 'possible', 'possibly', 'post', 'pot', 'potato',
    'potential', 'potentially', 'pound', 'pour', 'poverty', 'powder', 'power', 'powerful', 'practical', 'practice',
    'pray', 'prayer', 'precisely', 'predict', 'prefer', 'preference', 'pregnancy', 'pregnant', 'preliminary', 'preparation',
    'prepare', 'prescription', 'presence', 'present', 'presentation', 'preserve', 'president', 'presidential', 'press', 'pressure',
    'pretend', 'pretty', 'prevent', 'previous', 'previously', 'price', 'pride', 'priest', 'primarily', 'primary',
    'prime', 'principal', 'principle', 'print', 'prior', 'priority', 'prison', 'prisoner', 'privacy', 'private',
    'probably', 'problem', 'procedure', 'proceed', 'process', 'produce', 'producer', 'product', 'production', 'profession',
    'professional', 'professor', 'profile', 'profit', 'program', 'progress', 'project', 'prominent', 'promise', 'promote',
    'prompt', 'proof', 'proper', 'properly', 'property', 'proportion', 'proposal', 'propose', 'proposed', 'prosecutor',
    'prospect', 'protect', 'protection', 'protein', 'protest', 'proud', 'prove', 'provide', 'provider', 'province',
    'provision', 'psychological', 'psychologist', 'psychology', 'public', 'publication', 'publicly', 'publish', 'publisher', 'pull',
    'punishment', 'purchase', 'pure', 'purpose', 'pursue', 'push', 'put', 'qualify', 'quality', 'quarter',
    'question', 'quick', 'quickly', 'quiet', 'quietly', 'quit', 'quite', 'quote', 'race', 'racial',
    'radical', 'radio', 'rail', 'rain', 'raise', 'range', 'rank', 'rapid', 'rapidly', 'rare',
    'rarely', 'rate', 'rather', 'rating', 'ratio', 'raw', 'reach', 'react', 'reaction', 'read',
    'reader', 'reading', 'ready', 'real', 'reality', 'realize', 'really', 'reason', 'reasonable', 'reasonably',
    'recall', 'receive', 'recent', 'recently', 'recognize', 'recommend', 'recommendation', 'record', 'recover', 'recovery',
    'recruit', 'red', 'reduce', 'reduction', 'refer', 'reference', 'reflect', 'reflection', 'reform', 'refugee',
    'refuse', 'regard', 'regarding', 'regardless', 'region', 'regional', 'register', 'regular', 'regularly', 'regulation',
    'reject', 'relate', 'relation', 'relationship', 'relative', 'relatively', 'relax', 'release', 'relevant', 'reliable',
    'relief', 'religion', 'religious', 'reluctant', 'rely', 'remain', 'remaining', 'remarkable', 'remember', 'remind',
    'removal', 'remove', 'repeat', 'repeatedly', 'replace', 'reply', 'report', 'reporter', 'represent', 'representation',
    'representative', 'reputation', 'request', 'require', 'requirement', 'rescue', 'research', 'researcher', 'resemble', 'reservation',
    'reserve', 'resident', 'resist', 'resistance', 'resolution', 'resolve', 'resource', 'respect', 'respond', 'response',
    'responsibility', 'responsible', 'rest', 'restaurant', 'restore', 'restriction', 'result', 'retain', 'retire', 'retirement',
    'return', 'reveal', 'revenue', 'review', 'revolution', 'rich', 'rid', 'ride', 'rider', 'rifle',
    'right', 'ring', 'rise', 'risk', 'risky', 'rival', 'river', 'road', 'rob', 'rock',
    'role', 'roll', 'romantic', 'roof', 'room', 'root', 'rope', 'rose', 'rotate', 'rough',
    'roughly', 'round', 'route', 'routine', 'row', 'rub', 'rule', 'ruler', 'rumor', 'run',
    'running', 'rural', 'rush', 'russian', 'sacred', 'sad', 'safe', 'safety', 'sake', 'salad',
    'salary', 'sale', 'sales', 'salt', 'same', 'sample', 'sanction', 'sand', 'satellite', 'satisfaction',
    'satisfy', 'sauce', 'save', 'saving', 'savings', 'say', 'scale', 'scandal', 'scared', 'scenario',
    'scene', 'schedule', 'scheme', 'scholar', 'scholarship', 'school', 'science', 'scientific', 'scientist', 'scope',
    'score', 'scratch', 'screen', 'script', 'sea', 'search', 'season', 'seat', 'second', 'secondary',
    'secret', 'secretary', 'section', 'sector', 'secure', 'security', 'see', 'seed', 'seek', 'seem',
    'seen', 'select', 'selection', 'self', 'sell', 'senate', 'senator', 'send', 'senior', 'sense',
    'sensitive', 'sentence', 'separate', 'sequence', 'series', 'serious', 'seriously', 'serve', 'service', 'session',
    'set', 'setting', 'settle', 'settlement', 'setup', 'seven', 'several', 'severe', 'sex', 'sexual',
    'shade', 'shadow', 'shake', 'shall', 'shame', 'shape', 'share', 'sharp', 'she', 'sheet',
    'shelf', 'shell', 'shelter', 'shift', 'shine', 'ship', 'shirt', 'shock', 'shoe', 'shoot',
    'shooting', 'shop', 'shopping', 'shore', 'short', 'shortly', 'shot', 'should', 'shoulder', 'shout',
    'show', 'shown', 'sick', 'side', 'sight', 'sign', 'signal', 'significant', 'significantly', 'silence',
    'silent', 'silver', 'similar', 'similarly', 'simple', 'simply', 'simultaneously', 'sin', 'since', 'sing',
    'singer', 'single', 'sink', 'sir', 'sister', 'sit', 'site', 'situation', 'six', 'size',
    'ski', 'skill', 'skin', 'sky', 'slave', 'sleep', 'slice', 'slide', 'slight', 'slightly',
    'slip', 'slow', 'slowly', 'small', 'smart', 'smell', 'smile', 'smoke', 'smooth', 'snap',
    'snow', 'so', 'soap', 'soccer', 'social', 'society', 'sock', 'soft', 'software', 'soil',
    'solar', 'soldier', 'solid', 'solution', 'solve', 'some', 'somebody', 'somehow', 'someone', 'something',
    'sometimes', 'somewhat', 'somewhere', 'son', 'song', 'soon', 'sophisticated', 'sort', 'soul', 'sound',
    'soup', 'source', 'south', 'southern', 'soviet', 'space', 'spare', 'speak', 'speaker', 'special',
    'specialist', 'species', 'specific', 'specifically', 'speech', 'speed', 'spend', 'spending', 'spin', 'spirit',
    'spiritual', 'spite', 'split', 'spokesman', 'sport', 'spot', 'spread', 'spring', 'square', 'squeeze',
    'stable', 'staff', 'stage', 'stake', 'stand', 'standard', 'standing', 'star', 'stare', 'start',
    'state', 'statement', 'station', 'statistics', 'status', 'stay', 'steady', 'steal', 'steel', 'step',
    'stick', 'still', 'stimulate', 'stock', 'stomach', 'stone', 'stop', 'storage', 'store', 'storm',
    'story', 'straight', 'strange', 'stranger', 'strategy', 'stream', 'street', 'strength', 'strengthen', 'stress',
    'stretch', 'strike', 'string', 'strip', 'stroke', 'strong', 'strongly', 'structure', 'struggle', 'stuck',
    'student', 'studio', 'study', 'stuff', 'stupid', 'style', 'subject', 'subsequent', 'substance', 'substantial',
    'succeed', 'success', 'successful', 'successfully', 'such', 'sudden', 'suddenly', 'sue', 'suffer', 'sufficient',
    'sugar', 'suggest', 'suggestion', 'suit', 'summer', 'summit', 'sun', 'super', 'supply', 'support',
    'supporter', 'suppose', 'suppress', 'sure', 'surely', 'surface', 'surgery', 'surprise', 'surprised', 'surprising',
    'surprisingly', 'surround', 'survey', 'survival', 'survive', 'survivor', 'suspect', 'sustain', 'swear', 'sweet',
    'swim', 'swing', 'switch', 'symbol', 'sympathy', 'symptom', 'system', 'table', 'tackle', 'tail',
    'take', 'tale', 'talent', 'talk', 'tall', 'tank', 'tap', 'tape', 'target', 'task',
    'taste', 'tax', 'taxpayer', 'tea', 'teach', 'teacher', 'teaching', 'team', 'tear', 'technical',
    'technique', 'technology', 'teen', 'teenage', 'teenager', 'telephone', 'television', 'tell', 'temperature', 'temporary',
    'ten', 'tend', 'tendency', 'tennis', 'tension', 'tent', 'term', 'terms', 'terrible', 'territory',
    'terror', 'terrorism', 'terrorist', 'test', 'testimony', 'testing', 'text', 'than', 'thank', 'thanks',
    'that', 'the', 'theater', 'their', 'them', 'theme', 'themselves', 'then', 'theory', 'therapy',
    'there', 'therefore', 'these', 'they', 'thick', 'thin', 'thing', 'think', 'thinking', 'third',
    'thirty', 'this', 'those', 'though', 'thought', 'thousand', 'threat', 'threaten', 'three', 'through',
    'throughout', 'throw', 'thus', 'ticket', 'tie', 'tight', 'time', 'tiny', 'tip', 'tire',
    'tired', 'tissue', 'title', 'to', 'tobacco', 'today', 'toe', 'together', 'tomato', 'tomorrow',
    'tone', 'tongue', 'tonight', 'too', 'tool', 'tooth', 'top', 'topic', 'total', 'totally',
    'touch', 'tough', 'tour', 'tourist', 'tournament', 'toward', 'towards', 'town', 'toy', 'track',
    'trade', 'tradition', 'traditional', 'traffic', 'tragedy', 'trail', 'train', 'training', 'transfer', 'transform',
    'transformation', 'transition', 'translate', 'transportation', 'trap', 'travel', 'treat', 'treatment', 'treaty', 'tree',
    'tremendous', 'trend', 'trial', 'tribe', 'trick', 'trip', 'troop', 'trouble', 'truck', 'true',
    'truly', 'trust', 'truth', 'try', 'tube', 'tunnel', 'turn', 'twelve', 'twenty', 'twice',
    'twin', 'two', 'type', 'typical', 'typically', 'ugly', 'ultimate', 'ultimately', 'unable', 'uncle',
    'under', 'undergo', 'understand', 'understanding', 'unfortunately', 'uniform', 'union', 'unique', 'unit', 'united',
    'universal', 'universe', 'university', 'unknown', 'unless', 'unlike', 'unlikely', 'until', 'unusual', 'up',
    'upon', 'upper', 'urban', 'urge', 'urgent', 'us', 'use', 'used', 'useful', 'user',
    'usual', 'usually', 'utility', 'vacation', 'valley', 'valuable', 'value', 'variable', 'variation', 'variety',
    'various', 'vast', 'vegetable', 'vehicle', 'venture', 'version', 'versus', 'very', 'vessel', 'veteran',
    'via', 'victim', 'victory', 'video', 'view', 'viewer', 'village', 'violate', 'violation', 'violence',
    'violent', 'virtually', 'virtue', 'virus', 'visible', 'vision', 'visit', 'visitor', 'visual', 'vital',
    'voice', 'volume', 'volunteer', 'vote', 'voter', 'vs', 'vulnerable', 'wage', 'wait', 'wake',
    'walk', 'wall', 'want', 'war', 'ward', 'warm', 'warn', 'warning', 'wash', 'waste',
    'watch', 'water', 'wave', 'way', 'we', 'weak', 'wealth', 'wealthy', 'weapon', 'wear',
    'weather', 'web', 'website', 'wedding', 'week', 'weekend', 'weekly', 'weight', 'welcome', 'welfare',
    'well', 'west', 'western', 'wet', 'what', 'whatever', 'wheel', 'when', 'whenever', 'where',
    'whereas', 'wherever', 'whether', 'which', 'while', 'white', 'who', 'whole', 'whom', 'whose',
    'why', 'wide', 'widely', 'wife', 'wild', 'will', 'willing', 'win', 'wind', 'window',
    'wine', 'wing', 'winner', 'winning', 'winter', 'wipe', 'wire', 'wisdom', 'wise', 'wish',
    'with', 'withdraw', 'within', 'without', 'witness', 'woman', 'wonder', 'wonderful', 'wood', 'wooden',
    'word', 'work', 'worker', 'working', 'workplace', 'works', 'workshop', 'world', 'worry', 'worth',
    'would', 'write', 'writer', 'writing', 'wrong', 'yard', 'yeah', 'year', 'yellow', 'yes',
    'yesterday', 'yet', 'yield', 'you', 'young', 'your', 'yours', 'yourself', 'youth', 'zone'
  ];
  
  const usedSeparator = separator || '-';
  let passphrase = [];
  let usedWords = new Set(); // Prevent word reuse
  
  // Generate unique words
  for (let i = 0; i < wordCount; i++) {
    let attempts = 0;
    let word;
    
    // Find a unique word (max 100 attempts to prevent infinite loop)
    do {
      const randomIndex = crypto.randomInt(0, words.length);
      word = words[randomIndex];
      attempts++;
    } while (usedWords.has(word) && attempts < 100);
    
    usedWords.add(word);
    
    // Capitalize first letter of each word
    const capitalizedWord = word.charAt(0).toUpperCase() + word.slice(1);
    passphrase.push(capitalizedWord);
  }
  
  return passphrase.join(usedSeparator);
}

// Cleanup is now handled automatically by the storage backends

app.post('/api/store', createLimiter, async (req, res) => {
  try {
    let { encryptedData, iv, expirationMinutes } = req.body;

    if (!encryptedData || !iv || !expirationMinutes) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Security: Sanitize and validate inputs
    encryptedData = sanitizeString(encryptedData, MAX_SECRET_LENGTH * 3);
    iv = sanitizeString(iv, 1000);

    if (!encryptedData || !iv) {
      return res.status(400).json({ error: 'Invalid data format after sanitization' });
    }

    // Additional validation for base64 format
    const base64Pattern = /^[A-Za-z0-9+/=_-]+$/;
    if (!base64Pattern.test(encryptedData) || !base64Pattern.test(iv)) {
      return res.status(400).json({ error: 'Invalid encryption data format' });
    }

    // Validate encrypted data length
    if (encryptedData.length > MAX_SECRET_LENGTH * 2) {
      return res.status(400).json({ error: `Secret too long (max ${MAX_SECRET_LENGTH} characters)` });
    }

    const expiration = parseInt(expirationMinutes);
    if (isNaN(expiration) || expiration < 1 || expiration > 10080) { // max 7 days
      return res.status(400).json({ error: 'Invalid expiration time' });
    }

    const id = generateSecureId();

    try {
      const result = await storage.setSecret(id, { encryptedData, iv }, expiration);

      res.json({
        id,
        expiresAt: new Date(result.expiresAt).toISOString()
      });

    } catch (storageError) {
      console.error('Storage error:', storageError);
      res.status(503).json({ error: 'Storage service unavailable. Please try again.' });
    }

  } catch (error) {
    console.error('Store error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/retrieve/:id', retrieveLimiter, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid ID' });
    }

    try {
      const secretData = await storage.getAndDeleteSecret(id);

      if (!secretData) {
        return res.status(404).json({ error: 'Secret not found or expired' });
      }

      res.json({
        encryptedData: secretData.encryptedData,
        iv: secretData.iv
      });

    } catch (storageError) {
      console.error('Storage error during retrieval:', storageError);
      res.status(503).json({ error: 'Storage service unavailable. Please try again.' });
    }

  } catch (error) {
    console.error('Retrieve error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/config', (req, res) => {
  res.json({
    maxSecretLength: MAX_SECRET_LENGTH,
    passwordConfig: {
      excludeChars: PASSWORD_EXCLUDE_CHARS,
      specialChars: PASSWORD_SPECIAL_CHARS,
      defaultSeparator: '-'
    }
  });
});

app.post('/api/generate-password', (req, res) => {
  try {
    const { type, length, wordCount, separator } = req.body;
    
    // Security: Validate and sanitize all inputs
    const validation = validateAndSanitizeGeneratorInput(type, length, wordCount, separator);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }
    
    const { type: safeType, length: safeLength, wordCount: safeWordCount, separator: safeSeparator } = validation.sanitized;
    
    if (safeType === 'password') {
      const password = generatePassword(safeLength);
      
      // Additional security check
      if (!password || password.length !== safeLength) {
        throw new Error('Password generation validation failed');
      }
      
      res.json({ password });
      
    } else if (safeType === 'passphrase') {
      const passphrase = generatePassphrase(safeWordCount, safeSeparator);
      
      // Additional security check
      const passphraseWords = passphrase.split(safeSeparator || '-');
      if (passphraseWords.length !== safeWordCount) {
        throw new Error('Passphrase generation validation failed');
      }
      
      res.json({ password: passphrase });
    }
    
  } catch (error) {
    console.error('Password generation error:', error);
    res.status(500).json({ 
      error: error.message || 'Failed to generate password. Please try again.' 
    });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    const stats = await storage.getStats();
    const isHealthy = await storage.healthCheck();

    res.json({
      status: isHealthy ? 'ok' : 'degraded',
      storage: stats,
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      status: 'error',
      error: 'Health check failed',
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/view/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// HTTPS configuration for development
const useHTTPS = process.env.USE_HTTPS === 'true' || fs.existsSync('cert.pem');

// Initialize storage and start server
async function startServer() {
  try {
    // Initialize storage to determine backend
    await storage.initialize();

    if (useHTTPS && fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
  const httpsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };

  https.createServer(httpsOptions, app).listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 Secure password share server running on HTTPS port ${PORT}`);
      console.log(`🌐 Access at: https://localhost:${PORT}`);
      console.log(`📝 Note: You'll need to accept the self-signed certificate`);
      console.log(`💾 ${storage.backend} storage initialized`);
    });
  } else {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Secure password share server running on HTTP port ${PORT}`);
      console.log(`🌐 Access at: http://localhost:${PORT}`);
      console.log(`💾 ${storage.backend} storage initialized`);
    });
  }

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Vercel serverless function export
module.exports = app;

// Start server only when not running in Vercel serverless environment
if (process.env.NODE_ENV !== 'production' || process.env.VERCEL !== '1') {
  startServer();
}