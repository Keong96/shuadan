const express = require('express');
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { Client } = require('pg');
require('dotenv').config();
const app = express();
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public', { index: false }));

const languages = {
  en: JSON.parse(fs.readFileSync(path.join(__dirname, 'public/lang/en.json'), 'utf8')),
  zh: JSON.parse(fs.readFileSync(path.join(__dirname, 'public/lang/zh.json'), 'utf8'))
};

function t(lang = 'en', key) {
  return languages[lang]?.[key] || languages['en'][key] || key;
}

const config = {
  connectionString: process.env.DB
};

const client = new Client(config);
client.connect();

function GenerateJWT(userId, username, userStatus, userType) {
  return jwt.sign(
    { userId, username, userStatus, userType },
    process.env.TOKEN_KEY,
    { expiresIn: "24h" }
  );
}

function GenerateAdminJWT(adminId, adminName, userStatus, userType) {
  return jwt.sign(
    { userId: adminId, username: adminName, userStatus, userType },
    process.env.TOKEN_KEY,
    { expiresIn: "24h" }
  );
}

async function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.TOKEN_KEY, async (err, user) => {
    if (err) return res.sendStatus(403);

    try {
      const result = await client.query('SELECT status FROM users WHERE id = $1', [user.userId]);
      if (result.rows.length === 0) return res.sendStatus(403);

      if (!result.rows[0].status) {
        return res.status(200).json({ redirect: "/account-locked.html" });
      }

      req.user = user;
      next();
    } catch (error) {
      return res.sendStatus(500);
    }
  });
}

async function verifyAdminToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);

    const result = await client.query('SELECT id, user_type FROM users WHERE id = $1', [decoded.userId]);

    if (result.rows.length === 0 || (result.rows[0].user_type !== 0 && result.rows[0].user_type !== 1)) {
      return res.sendStatus(403);
    }

    req.admin = {
      adminId: decoded.adminId,
      adminName: decoded.adminName,
      userType: result.rows[0].user_type
    };

    next();
  } catch (err) {
    console.error(err);
    return res.sendStatus(403);
  }
}

function generateReferralCode(length = 6) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let code = ''
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return code
}

// Routing
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Endpoint

app.get('/company-name', async (req, res) => {
  try {
    const result = await client.query(
      "SELECT value FROM config WHERE key = 'company_name' LIMIT 1"
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'company_name not found' })
    }

    res.json({ success: true, company_name: result.rows[0].value })
  } catch (err) {
    console.error('Error fetching company name:', err)
    res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1 AND password = $2 AND deleted_at IS NULL', [username, password]);
    const user = result.rows[0];

    if (!user) {
      return res.status(200).json({
        status: false,
        data: {},
        message: t(lang, 'error.login.invalidCredentials'),
      });
    }

    if (!user.status) {
      return res.status(200).json({
        status: false,
        data: {},
        message: t(lang, 'error.login.locked'),
      });
    }

    // 统一字段结构生成 JWT
    const token = (user.user_type === 0 || user.user_type === 1)
      ? GenerateAdminJWT(user.id, user.username, user.status, user.user_type)
      : GenerateJWT(user.id, user.username, user.status, user.user_type);

    return res.json({
      status: true,
      data: { token },
      message: ""
    });

  } catch (err) {
    console.error(err);
    return res.status(200).json({
      status: false,
      data: {},
      message: t(lang, 'error.server') || 'Server Error'
    });
  }
})

app.post('/register', async (req, res) => {
  const { username, password, securityPin, phone, email, gender, dob, referralCode, lang } = req.body;

  if (!username || !password || !securityPin)
    return res.status(400).json({ status: false, message: t('error.missing_fields') });

  try {
    // Check if username exists
    const check = await client.query(
      'SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL',
      [username]
    );
    if (check.rowCount > 0)
      return res.status(409).json({ status: false, message: t('error.register.usernameTaken') });

    let referred_by = null;

    if (referralCode) {
      const ref = await client.query(
        'SELECT id FROM users WHERE referral_code = $1 AND deleted_at IS NULL',
        [referralCode]
      );
      if (ref.rowCount > 0) referred_by = ref.rows[0].id;
    }

    let selfReferralCode;

    while (true) {
      const tempCode = generateReferralCode()
      const check = await client.query('SELECT 1 FROM users WHERE referral_code = $1', [tempCode])
      if (check.rowCount === 0) {
        selfReferralCode = tempCode
        break
      }
    }

    await client.query(
      `INSERT INTO users 
        (username, password, security_pin, phone, email, gender, dob, referral_code, referred_by, status, user_type, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, 2, NOW())`,
      [username, password, securityPin, phone, email, gender, dob, selfReferralCode, referred_by]
    )

    res.json({ status: true, message: t('success.register') });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ status: false, message: t('error.server') });
  }
});

app.get('/me', verifyToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const userRes = await client.query(`
      SELECT id, username, phone, email, gender, to_char(dob, 'YYYY-MM-DD') AS dob, balance, referral_code, credit_score, vip_level
      FROM users
      WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!userRes.rows.length)
      return res.status(404).json({ status: false });

    const user = userRes.rows[0];

    // 当前激活 cycle
    const cycleRes = await client.query(`
      SELECT id, cycle_size, orders
      FROM cycles
      WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL
      ORDER BY id DESC LIMIT 1
    `, [userId]);

    let completion_ratio = '0/0';
    if (cycleRes.rows.length > 0) {
      const cycle = cycleRes.rows[0];
      const currentCompleted = Array.isArray(cycle.orders) ? cycle.orders.length : 0;
      completion_ratio = `${currentCompleted}/${cycle.cycle_size}`;
    }

    // 所有已完成订单数量
    const completedRes = await client.query(`
      SELECT COUNT(*) FROM orders 
      WHERE user_id = $1 AND status = 'COMPLETED' AND deleted_at IS NULL
    `, [userId]);
    const tasks_completed = parseInt(completedRes.rows[0].count, 10);

    // 今日收益
    const profitRes = await client.query(`
      SELECT COALESCE(SUM(commission), 0) AS total 
      FROM orders 
      WHERE user_id = $1 
        AND status = 'COMPLETED' 
        AND deleted_at IS NULL 
        AND DATE(completed_at) = CURRENT_DATE
    `, [userId]);
    const daily_profit = parseFloat(profitRes.rows[0].total).toFixed(2);

    res.json({
      status: true,
      profile: {
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        gender: user.gender,
        dob: user.dob,
        referral_code: user.referral_code,
        credit_score: user.credit_score,
        vip_level: user.vip_level,
        balance: user.balance,
        daily_profit: daily_profit,
        tasks_completed: tasks_completed,
        completion_ratio: completion_ratio
      }
    });

  } catch (err) {
    console.error('/me error:', err);
    res.status(500).json({ status: false });
  }
});

app.get('/my-transactions', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const lang = req.headers['accept-language'] || 'en';

    const { rows } = await client.query(`
      SELECT id, amount, type, status, remark, created_at
      FROM transactions
      WHERE user_id = $1 AND deleted_at IS NULL
      ORDER BY created_at DESC
    `, [userId]);

    const data = rows.map(tx => ({
      ...tx,
      type_label: t(lang, `funds.type.${tx.type.toLowerCase()}`),
      status_label: t(lang, `funds.status.${tx.status.toLowerCase()}`)
    }));

    res.json({ status: true, data });
  } catch (err) {
    console.error('GET /my-transactions', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/orders', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const lang = req.headers['accept-language'] || 'en';

  try {
    const result = await client.query(`
      SELECT 
        o.id, o.amount, o.commission, o.status, o.created_at,
        t.product_name, t.image_url
      FROM orders o
      JOIN tasks t ON o.task_id = t.id
      WHERE o.user_id = $1 AND o.deleted_at IS NULL
      ORDER BY o.created_at DESC
    `, [userId]);

    res.json({ status: true, data: result.rows });

  } catch (err) {
    console.error('GET /orders', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/orders', verifyToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    // 读取必要 config：vip_tiers, blocker_indexes
    const cfgRes = await client.query(
      "SELECT key, value FROM config WHERE key IN ('vip_tiers','blocker_indexes')"
    );
    const cfgMap = Object.fromEntries(cfgRes.rows.map(r => [r.key, r.value || '']));

    // 解析 vip_tiers JSON
    let vipTiers = {};
    try { vipTiers = JSON.parse(cfgMap.vip_tiers || '{}'); } catch (e) { vipTiers = {}; }

    // 解析 blocker_indexes -> 数组 of int
    const blockerIndexes = (cfgMap.blocker_indexes || '')
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !Number.isNaN(n));

    // 读取用户 vip_level（若无，默认 BASIC）
    const ures = await client.query("SELECT vip_level FROM users WHERE id = $1", [userId]);
    const vipLevel = (ures.rows[0] && ures.rows[0].vip_level) ? ures.rows[0].vip_level : 'BASIC';

    // 取该 vip 的配置（如果没在 config 里，做 fallback）
    const vipCfg = vipTiers[vipLevel] || vipTiers['BASIC'] || { cycle_size: 20, commission_rate: 0.03 };
    const vipCycleSize = parseInt(vipCfg.cycle_size, 10) || 20;
    const vipCommissionRate = parseFloat(vipCfg.commission_rate) || 0.03;

    // 2) 查找激活周期（status = TRUE）
    let cr = await client.query(
      "SELECT id, orders, cycle_size, blocker_indexes, commission_amount, commission_rate FROM cycles WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL ORDER BY id DESC LIMIT 1",
      [userId]
    );
    let cycle = cr.rows[0];

    // 3) 如果没有激活周期，就按用户 vip 创建一个新的（把 blocker_indexes、cycle_size、commission_rate 写入 cycle）
    if (!cycle) {
      // blocker_indexes 存为 int[]，用上面解析的全局 blockerIndexes（或者你也可以把 blocker_indexes 存在 vipCfg）
      const blockerArray = blockerIndexes.length ? blockerIndexes : null; // pass null if empty
      const ins = await client.query(
        `INSERT INTO cycles (user_id, cycle_size, blocker_indexes, commission_rate, commission_amount, orders, status, created_at)
         VALUES ($1, $2, $3, $4, 0, '{}', TRUE, NOW())
         RETURNING id, orders, cycle_size, blocker_indexes, commission_amount, commission_rate`,
        [userId, vipCycleSize, blockerArray, vipCommissionRate]
      );
      cycle = ins.rows[0];
    }

    // 4) 如果当前周期已完成（订单数 >= cycle_size），返回待领佣金
    const completedCount = Array.isArray(cycle.orders) ? cycle.orders.length : 0;
    if (completedCount >= cycle.cycle_size) {
      return res.json({
        status: true,
        data: parseFloat(cycle.commission_amount || 0).toFixed(2)
      });
    }

    // 5) 检查是否已有未完成的 pending 订单
    const pending = await client.query(
      `SELECT o.id, o.amount, o.commission, t.product_name, t.product_description, t.image_url
       FROM orders o
       JOIN tasks t ON o.task_id = t.id
       WHERE o.user_id = $1 AND o.cycle_id = $2 AND o.status = 'PENDING' AND o.deleted_at IS NULL
       LIMIT 1`,
      [userId, cycle.id]
    );
    if (pending.rowCount) {
      const o = pending.rows[0];
      return res.json({
        status: true,
        data: {
          orderId: o.id,
          amount: o.amount,
          commission: o.commission,
          productName: o.product_name,
          productDescription: o.product_description,
          productImage: o.image_url
        }
      });
    }

    // 6) 计算 idx，判断是否是 blocker（以 cycle.blocker_indexes 为准）
    const idx = completedCount + 1;
    const cycleBlockers = Array.isArray(cycle.blocker_indexes) ? cycle.blocker_indexes : blockerIndexes;
    const isBlocker = Array.isArray(cycleBlockers) && cycleBlockers.includes(idx);

    // 7) 随机选 task（task 表必须有 product_price 与 blocker_price 字段）
    const taskRes = await client.query("SELECT id, product_name, product_description, image_url, product_price, blocker_price FROM tasks WHERE deleted_at IS NULL ORDER BY RANDOM() LIMIT 1");
    if (taskRes.rowCount === 0) {
      return res.status(400).json({ status: false, message: 'No available tasks' });
    }
    const task = taskRes.rows[0];

    // 8) 金额直接取 task 中的价格；佣金以 cycle.commission_rate（已经为小数）计算
    const amount = parseFloat(isBlocker ? task.blocker_price : task.product_price);
    if (Number.isNaN(amount)) return res.status(400).json({ status: false, message: 'Invalid task price' });

    const commission = parseFloat((amount * parseFloat(cycle.commission_rate || vipCommissionRate)).toFixed(2));

    // 9) 插入订单（状态 PENDING），并把 order id append 到 cycles.orders（不改变 commission_amount）
    const or = await client.query(
      `INSERT INTO orders (user_id, cycle_id, task_id, amount, commission, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 'PENDING', NOW())
       RETURNING id, amount, commission`,
      [userId, cycle.id, task.id, amount, commission]
    );

    await client.query(
      `UPDATE cycles SET orders = array_append(COALESCE(orders, '{}'), $1) WHERE id = $2`,
      [or.rows[0].id, cycle.id]
    );

    // 10) 返回新订单给前端
    res.json({
      status: true,
      data: {
        orderId: or.rows[0].id,
        amount: or.rows[0].amount,
        commission: or.rows[0].commission,
        productName: task.product_name,
        productDescription: task.product_description,
        productImage: task.image_url
      }
    });

  } catch (err) {
    console.error('/orders error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/orders/:id/review', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const orderId = req.params.id;
  const { rating, comment } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  try {
    const { rows } = await client.query(`
      SELECT * FROM orders 
      WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL AND status != 'COMPLETED'
    `, [orderId, userId]);

    if (!rows.length)
      return res.status(404).json({ status: false, message: t('error.orderNotFound') });

    const order = rows[0];
    const amount = parseFloat(order.amount);
    const commission = parseFloat(order.commission);

    const balRes = await client.query(`SELECT balance FROM users WHERE id = $1`, [userId]);
    if (!balRes.rows.length)
      return res.status(404).json({ status: false, message: t('error.userNotFound') });

    const balance = parseFloat(balRes.rows[0].balance);
    if (balance < amount)
      return res.status(400).json({ status: false, message: t('error.insufficientBalance') });

    await client.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [amount, userId]);

    await client.query(`
      INSERT INTO transactions (user_id, amount, type, status, remark) 
      VALUES ($1, $2, 'PURCHASE', 'APPROVED', $3)
    `, [userId, -amount, `#${orderId}`]);

    await client.query(`
      UPDATE orders 
      SET review_rating = $1, review_comment = $2, completed_at = CURRENT_TIMESTAMP, status = 'COMPLETED'
      WHERE id = $3
    `, [rating, comment, orderId]);

    await client.query(`
      UPDATE cycles 
      SET commission_amount = commission_amount + $1
      WHERE id = $2
    `, [commission, order.cycle_id]);

    res.json({ status: true });
  } catch (err) {
    console.error(`POST /orders/${orderId}/review`, err);
    res.status(500).json({ status: false, message: "Server Error" });
  }
});

app.post('/update-profile', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { contact, securityPin } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  if (!securityPin)
    return res.status(400).json({ status: false, message: t('error.pinRequired') });

  try {
    const result = await client.query(`
      SELECT security_pin FROM users WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!result.rowCount || result.rows[0].security_pin !== securityPin)
      return res.status(200).json({ status: false, message: t('error.invalidPin') });

    await client.query(`
      UPDATE users SET phone = $1, updated_at = NOW() WHERE id = $2
    `, [contact, userId]);

    res.json({ status: true });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ status: false, message: "Server Error"});
  }
});

app.post('/claim-commission', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  try {
    const { rows } = await client.query(`
      SELECT id, cycle_size, orders FROM cycles 
      WHERE user_id = $1 AND status = TRUE ORDER BY id DESC LIMIT 1
    `, [userId]);

    if (!rows.length)
      return res.status(400).json({ status: false, message: t('commission.claim.error.noActiveCycle') });

    const current = rows[0];

    if (current.orders.length < current.cycle_size)
      return res.status(400).json({ status: false, message: t('commission.claim.error.notCompleted') });

    const sumRes = await client.query(`
      SELECT SUM(commission)::numeric(10,2) AS total 
      FROM orders WHERE cycle_id = $1 AND user_id = $2 AND deleted_at IS NULL
    `, [current.id, userId]);

    const commission = parseFloat(sumRes.rows[0].total || 0);
    if (commission <= 0)
      return res.status(400).json({ status: false, message: t('commission.claim.error.noCommission') });

    const downlineRate = 0.25;
    const ures = await client.query(`SELECT referred_by FROM users WHERE id = $1`, [userId]);
    const referredBy = ures.rows[0] ? ures.rows[0].referred_by : null;

    if (referredBy) {
      const refererShare = parseFloat((commission * downlineRate).toFixed(2));
      if (refererShare > 0) {
        const remark = `Downline share from user ${userId} cycle ${current.id}`;
        await client.query(`
          INSERT INTO transactions (user_id, type, amount, status, remark)
          VALUES ($1, 'COMMISSION', $2, 'PENDING', $3)
        `, [referredBy, refererShare, remark]);
      }
    }

    await client.query(`
      INSERT INTO transactions (user_id, type, amount, status, remark) 
      VALUES ($1, 'COMMISSION', $2, 'PENDING', $3)
    `, [userId, commission, ``]);

    await client.query(`UPDATE cycles SET status = FALSE, finished_at = NOW() WHERE id = $1`, [current.id]);

    const configRes = await client.query(`
      SELECT key, value FROM config WHERE key IN ('cycle_size', 'blocker_indexes')
    `);
    const cfgMap = Object.fromEntries(configRes.rows.map(r => [r.key, r.value]));
    const newSize = parseInt(cfgMap['cycle_size'], 10);
    const blockerIndexes = cfgMap['blocker_indexes'].split(',').map(n => parseInt(n, 10));

    await client.query(`
      INSERT INTO cycles (user_id, cycle_size, blocker_indexes) 
      VALUES ($1, $2, $3)
    `, [userId, newSize, blockerIndexes]);

    res.json({ status: true });
  } catch (err) {
    console.error('POST /claim-commission error:', err);
    res.status(500).json({ status: false, message: "Server Error" });
  }
});

app.post('/withdraw', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { amount, pin } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  if (!amount || isNaN(amount) || amount <= 0)
    return res.status(400).json({ status: false, message: t('error.invalidAmount') });

  if (!/^\d{6}$/.test(pin))
    return res.status(400).json({ status: false, message: t('error.invalidPin') });

  try {
    // 获取用户资料（包含 balance 和 security_pin）
    const userRes = await client.query(`
      SELECT balance, security_pin FROM users 
      WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!userRes.rows.length)
      return res.status(404).json({ status: false, message: t('error.userNotFound') });

    const user = userRes.rows[0];
    const balance = parseFloat(user.balance);

    // 验证 PIN 是否匹配
    if (user.security_pin !== pin)
      return res.status(400).json({ status: false, message: t('error.incorrectPin') });

    // 验证余额
    if (balance < amount)
      return res.status(400).json({ status: false, message: t('error.insufficientBalance') });

    // 插入 transaction
    await client.query(`
      INSERT INTO transactions (user_id, amount, type, status, remark)
      VALUES ($1, $2, 'WITHDRAWAL', 'PENDING', $3)
    `, [userId, -Math.abs(amount), ""]);

    // 立即扣除余额
    await client.query(`
      UPDATE users SET balance = balance - $1 WHERE id = $2
    `, [amount, userId]);

    res.json({ status: true });

  } catch (err) {
    console.error('POST /withdraw', err);
    res.status(500).json({ status: false, message: "Server Error" });
  }
});

app.get('/team', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const { rows } = await client.query(`
      SELECT
        u.id,
        u.username,
        u.vip_level,
        COALESCE(SUM(CASE WHEN o.status = 'COMPLETED' THEN o.commission ELSE 0 END), 0) AS downline_commission
      FROM users u
      LEFT JOIN orders o
        ON o.user_id = u.id
       AND o.deleted_at IS NULL
      WHERE u.referred_by = $1
        AND u.deleted_at IS NULL
      GROUP BY u.id, u.username, u.vip_level
      ORDER BY u.id DESC
    `, [userId]);

    const data = rows.map(r => ({
      username: r.username,
      vip_level: r.vip_level,
      commission_amount: Number(r.downline_commission) * 0.25
    }));

    res.json({ status: true, data });
  } catch (err) {
    console.error('Error fetching user team:', err);
    res.status(500).json({ status: false, error: 'Failed to fetch team' });
  }
});

// Admin
app.get('/users', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(`
      SELECT id, username, password, security_pin, phone, email, gender,
        TO_CHAR(dob, 'YYYY-MM-DD') AS dob, balance, referral_code, referred_by,
        status, user_type, vip_level, credit_score, last_login, created_at
      FROM users
      WHERE user_type = 2 AND deleted_at IS NULL
      ORDER BY id ASC
    `);

    res.json({
      status: true,
      data: result.rows
    });
  } catch (err) {
    console.error('Error fetching admin users:', err);
    res.status(500).json({
      status: false,
      error: 'Failed to fetch users'
    });
  }
});

app.get('/config', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(`
      SELECT key, value, updated_at
      FROM config
      ORDER BY key ASC
    `);

    if (!result.rows.length) return res.json({ status: false });

    return res.status(200).json({
      status: true,
      data: result.rows
    });

  } catch (err) {
    console.error('Error fetching config:', err);
    res.status(500).json({ status: false });
  }
});

app.post('/user/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { password, security_pin, phone, email, gender, dob } = req.body;

  if (!id) return res.status(400).json({ message: 'Invalid ID' });

  try {
    const result = await client.query(
      `UPDATE users SET password=$1, security_pin=$2, phone=$3, email=$4, gender=$5, dob=$6 WHERE id=$7`,
      [password, security_pin, phone, email, gender, dob, id]
    );

    if (result.rowCount === 0) return res.status(404).json({ status: false, message: 'User not found' });

    res.json({ status: true, message: 'User updated' });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.patch('/user/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (typeof status !== 'boolean') {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  try {
    const result = await client.query(
      'UPDATE users SET status=$1 WHERE id=$2',
      [status, id]
    );

    if (result.rowCount === 0) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'Status updated' });
  } catch (err) {
    console.error('Update status error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/tasks', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(
      'SELECT * FROM tasks WHERE deleted_at IS NULL ORDER BY id'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Fetch tasks failed' });
  }
});

app.get('/tasks/:id', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(
      'SELECT * FROM tasks WHERE id = $1 AND deleted_at IS NULL',
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Task not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Fetch task failed' });
  }
});

app.post('/tasks', verifyAdminToken, async (req, res) => {
  const { productName, imageUrl, taskDescription, productPrice, blockerPrice } = req.body;
  try {
    const result = await client.query(
      `INSERT INTO tasks (product_name, image_url, product_description, product_price, blocker_price)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [productName, imageUrl, taskDescription, productPrice, blockerPrice]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Create task failed' });
  }
});

app.put('/tasks/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { productName, imageUrl, taskDescription, productPrice, blockerPrice } = req.body;
  try {
    const result = await client.query(
      `UPDATE tasks 
       SET product_name = $1, 
           image_url = $2, 
           product_description = $3,
           product_price = $4,
           blocker_price = $5
       WHERE id = $6 AND deleted_at IS NULL 
       RETURNING *`,
      [productName, imageUrl, taskDescription, productPrice, blockerPrice, id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Task not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/tasks/:id', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(
      `UPDATE tasks SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING id`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Task not found or already deleted' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.put('/orders/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, commission_rate } = req.body;

    const result = await client.query(`
      UPDATE orders SET amount = $1, commission = $2
      WHERE id = $3 AND deleted_at IS NULL
      RETURNING *, cycle_id;
  `, [amount, (amount * commission_rate / 100), id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ status: false, error: 'Order not found' });
    }

    const order = result.rows[0];

    await client.query(`
      UPDATE cycles
      SET commission_amount = (
        SELECT COALESCE(SUM(o.commission), 0)
        FROM orders o
        WHERE o.id = ANY(cycles.orders) 
          AND o.status = 'COMPLETED'
          AND o.deleted_at IS NULL
      )
      WHERE id = $1;
    `, [order.cycle_id]);

    res.json({ status: true, data: order });
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ status: false, error: 'Update failed' });
  }
});

app.get('/cycles', verifyAdminToken, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ status: false, error: 'Missing userId' });
    }

    const cyclesResult = await client.query(`
      SELECT c.*, u.username
      FROM cycles c
      LEFT JOIN users u ON u.id = c.user_id
      WHERE c.deleted_at IS NULL
        AND c.status = TRUE
        AND c.user_id = $1
      ORDER BY c.id DESC
      LIMIT 1
    `, [userId]);

    if (cyclesResult.rowCount === 0) {
      return res.json({ status: true, data: [] });
    }

    const activeCycle = cyclesResult.rows[0];

    const ordersResult = await client.query(`
      SELECT o.*, 
            u.username AS order_username,
            t.product_name,
            t.image_url
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      LEFT JOIN tasks t ON t.id = o.task_id
      WHERE o.cycle_id = $1
      ORDER BY 
        CASE WHEN o.completed_at IS NULL THEN 1 ELSE 0 END,
        o.completed_at ASC
    `, [activeCycle.id]);

    activeCycle.orders = ordersResult.rows;
    activeCycle.commission_rate = parseFloat(activeCycle.commission_rate) || 0;

    res.json({ status: true, data: [activeCycle] });

  } catch (err) {
    console.error('Error fetching cycles:', err);
    res.status(500).json({ status: false, error: 'Fetch failed' });
  }
});

app.post('/cycle/reset', verifyAdminToken, async (req, res) => {
  const userId = req.body.userId;
  if (!userId) return res.status(400).json({ status: false, error: 'Missing userId' });

  try {
    // 先读取当前 active cycle 的设置（取最新一笔 active）
    const cur = await client.query(
      `SELECT id, cycle_size, blocker_indexes, commission_rate
       FROM cycles
       WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL
       ORDER BY id DESC
       LIMIT 1`,
      [userId]
    );

    // 按你说的：假设一定存在 active cycle（所以不做不存在的判定）
    const old = cur.rows[0];

    // 关闭该 cycle，并拿到 commission_amount（关闭时写 finished_at）
    const upd = await client.query(
      `UPDATE cycles
       SET status = FALSE, finished_at = NOW()
       WHERE id = $1
       RETURNING commission_amount`,
      [old.id]
    );

    const commissionAmount = parseFloat(upd.rows[0]?.commission_amount || 0);

    // 1) 给用户发放佣金（直接插入 transaction 并更新用户余额）
    if (commissionAmount > 0) {
      await client.query(
        `INSERT INTO transactions (user_id, amount, type, status, remark, created_at)
         VALUES ($1, $2, 'COMMISSION', 'APPROVED', $3, NOW())`,
        [userId, commissionAmount, ``]
      );

      await client.query(
        `UPDATE users SET balance = balance + $1 WHERE id = $2`,
        [commissionAmount, userId]
      );
    }

    // 2) 给上级分成（固定 25%）
    const downlineRate = 0.25;
    const ures = await client.query(`SELECT referred_by FROM users WHERE id = $1`, [userId]);
    const referredBy = ures.rows[0]?.referred_by || null;

    if (referredBy && commissionAmount > 0) {
      const refererShare = parseFloat((commissionAmount * downlineRate).toFixed(2));
      if (refererShare > 0) {
        await client.query(
          `INSERT INTO transactions (user_id, amount, type, status, remark, created_at)
           VALUES ($1, $2, 'COMMISSION', 'APPROVED', $3, NOW())`,
          [referredBy, refererShare, `Downline share from user ${userId} cycle ${old.id}`]
        );

        await client.query(
          `UPDATE users SET balance = balance + $1 WHERE id = $2`,
          [refererShare, referredBy]
        );
      }
    }

    // 3) 创建新 cycle（继承旧 cycle 的设置）
    await client.query(
      `INSERT INTO cycles (user_id, cycle_size, blocker_indexes, commission_rate, commission_amount, orders, status, created_at)
       VALUES ($1, $2, $3, $4, 0, '{}', TRUE, NOW())`,
      [
        userId,
        old.cycle_size || 20,
        old.blocker_indexes || null,
        parseFloat(old.commission_rate) || 0.03
      ]
    );

    // 只回 status true（不要多余字段）
    return res.json({ status: true });

  } catch (err) {
    console.error('POST /cycle/:userId/reset error:', err);
    return res.status(500).json({ status: false, error: 'Reset failed' });
  }
});

app.get('/transactions', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await client.query(`
      SELECT t.id, u.username, t.amount, t.type, t.status, t.remark, t.created_at
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.deleted_at IS NULL
      ORDER BY t.created_at DESC
    `);
    res.json({ status: true, data: rows });
  } catch (err) {
    console.error('GET /transactions', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/transactions', verifyAdminToken, async (req, res) => {
  const { userId, amount, type, status, remark } = req.body;
  try {
    const { rows } = await client.query(`
      INSERT INTO transactions (user_id, amount, type, status, remark)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id, amount, type, status, remark, created_at
    `, [userId, amount, type, status, remark]);
    res.json({ status: true, data: rows[0] });
  } catch (err) {
    console.error('POST /transactions', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.patch('/transactions/:id', verifyAdminToken, async (req, res) => {
  const txId    = parseInt(req.params.id, 10);
  const newStat = req.body.status;

  if (!['APPROVED', 'REJECTED'].includes(newStat)) {
    return res.status(400).json({ status: false, message: 'Invalid status' });
  }

  try {
    await client.query('BEGIN');

    // 1) 更新状态并取出交易详情
    const upd = await client.query(`
      UPDATE transactions
      SET status = $1
      WHERE id = $2 AND deleted_at IS NULL
      RETURNING id, user_id, amount, type
    `, [newStat, txId]);

    if (!upd.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ status: false, message: 'Transaction not found' });
    }

    const { user_id, amount, type } = upd.rows[0];

    // 2) 若 APPROVED，处理入账或出账
    if (newStat === 'APPROVED') {
      const plusTypes = ['DEPOSIT', 'COMMISSION'];
      const delta = plusTypes.includes(type.toUpperCase()) ? amount : -amount;

      const ub = await client.query(`
        UPDATE users
        SET balance = balance + $1
        WHERE id = $2
        RETURNING balance
      `, [delta, user_id]);

      if (!ub.rowCount) {
        await client.query('ROLLBACK');
        return res.status(500).json({ status: false, message: 'Failed to update user balance' });
      }
    }

    // 3) 若是提现 且被拒绝，返还金额
    if (type.toUpperCase() === 'WITHDRAWAL' && newStat === 'REJECTED') {
      const refund = await client.query(`
        UPDATE users
        SET balance = balance + $1
        WHERE id = $2
        RETURNING balance
      `, [Math.abs(amount), user_id]);

      if (!refund.rowCount) {
        await client.query('ROLLBACK');
        return res.status(500).json({ status: false, message: 'Failed to refund user' });
      }
    }

    await client.query('COMMIT');
    res.json({ status: true, data: { id: txId, status: newStat } });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(`PATCH /transactions/${txId}`, err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.delete('/transactions/:id', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await client.query(`
      UPDATE transactions
      SET deleted_at = NOW()
      WHERE id = $1 AND deleted_at IS NULL
      RETURNING id
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ status: false, message: 'Not found or already deleted' });
    res.json({ status: true, data: { id: rows[0].id } });
  } catch (err) {
    console.error(`DELETE /transactions/${req.params.id}`, err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/team/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { rows } = await client.query(`
      SELECT
        u.id,
        u.username,
        u.vip_level,
        COALESCE(SUM(CASE WHEN o.status = 'COMPLETED' THEN o.commission ELSE 0 END), 0) AS downline_commission
      FROM users u
      LEFT JOIN orders o
        ON o.user_id = u.id
       AND o.deleted_at IS NULL
      WHERE u.referred_by = $1
        AND u.deleted_at IS NULL
      GROUP BY u.id, u.username, u.vip_level
      ORDER BY u.id DESC
    `, [id]);

    const data = rows.map(r => ({
      username: r.username,
      vip_level: r.vip_level,
      commission_amount: Number(r.downline_commission) * 0.25
    }));

    res.json({ status: true, data });
  } catch (err) {
    console.error('Error fetching admin team:', err);
    res.status(500).json({ status: false, error: 'Failed to fetch team' });
  }
});

app.get('/config', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM config ORDER BY key ASC');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching config:', err);
    res.status(500).json({ error: 'Failed to fetch config' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
