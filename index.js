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
  // zh: JSON.parse(fs.readFileSync(path.join(__dirname, 'public/lang/zh.json'), 'utf8')),
  de: JSON.parse(fs.readFileSync(path.join(__dirname, 'public/lang/de.json'), 'utf8')),
  fr: JSON.parse(fs.readFileSync(path.join(__dirname, 'public/lang/fr.json'), 'utf8'))
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
      return res.status(200).json({ success: false, message: 'company_name not found' })
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
  const { username, password, securityPin, phone, email, country, gender, dob, referralCode, lang } = req.body;
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;
  
  if (!username || !password || !securityPin)
    return res.status(200).json({ status: false, message: t('error.missing_fields') });

  try {
    // 检查用户名是否存在
    const check = await client.query(
      'SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL',
      [username]
    );
    if (check.rowCount > 0)
      return res.status(200).json({ status: false, message: t('error.register.usernameTaken') });

    // 获取推荐人
    let referred_by = null;
    if (referralCode) {
      const ref = await client.query(
        'SELECT id FROM users WHERE referral_code = $1 AND deleted_at IS NULL',
        [referralCode]
      );
      if (ref.rowCount > 0) referred_by = ref.rows[0].id;
    }

    // 生成唯一推荐码
    let selfReferralCode;
    while (true) {
      const tempCode = generateReferralCode();
      const check = await client.query('SELECT 1 FROM users WHERE referral_code = $1', [tempCode]);
      if (check.rowCount === 0) {
        selfReferralCode = tempCode;
        break;
      }
    }

    // === 从 config 表加载 vip_tiers ===
    const vipCfgRes = await client.query("SELECT value FROM config WHERE key = 'vip_tiers' LIMIT 1");
    let vipTiers = {};
    if (vipCfgRes.rowCount > 0) {
      try {
        vipTiers = JSON.parse(vipCfgRes.rows[0].value);
      } catch (e) {
        console.error('Invalid JSON in vip_tiers config:', e);
        vipTiers = {};
      }
    }

    // === 从 config 表加载 global_blockers ===
    const blockCfgRes = await client.query("SELECT value FROM config WHERE key = 'global_blockers' LIMIT 1");
    let globalBlockers = [12, 15, 18];
    if (blockCfgRes.rowCount > 0) {
      try {
        globalBlockers = JSON.parse(blockCfgRes.rows[0].value);
      } catch (e) {
        console.error('Invalid JSON in global_blockers config:', e);
      }
    }

    // === 创建用户 ===
    const defaultLuckyDrawSetting = JSON.stringify([
      { "name": "Discount coupons", "rate": 9 },
      { "name": "Reward $1999", "rate": 10 },
      { "name": "10g gold bar", "rate": 9 },
      { "name": "Iphone 17PM", "rate": 10 },
      { "name": "Reward $888", "rate": 19 },
      { "name": "First-class air tickets", "rate": 3 },
      { "name": "PS5/Nintendo switch", "rate": 4 },
      { "name": "LV brand", "rate": 3 },
      { "name": "Channel brand", "rate": 3 },
      { "name": "Reward $350", "rate": 10 },
      { "name": "Brand-name watches", "rate": 3 },
      { "name": "10,000 cash", "rate": 1 },
      { "name": "Re-spin one time", "rate": 8 },
      { "name": "NTL", "rate": 8 }
    ]);

    const insertUser = await client.query(
      `INSERT INTO users (username, password, security_pin, phone, email, country, gender, dob, referral_code, referred_by, status, user_type, balance, lucky_draw_setting, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,2,10.00,$11,NOW())
      RETURNING id`,
      [username, password, securityPin, phone, email, country, gender, dob, selfReferralCode, referred_by, defaultLuckyDrawSetting]
    )

    const userId = insertUser.rows[0].id;

    // === 初始赠送记录 ===
    await client.query(
      `INSERT INTO transactions (user_id, amount, type, status, remark, created_at)
       VALUES ($1,$2,$3,$4,$5,NOW())`,
      [userId, 10.00, 'DEPOSIT', 'APPROVED', 'New User Benefit']
    );

    // === 获取 VIP 等级与配置 ===
    const ures = await client.query("SELECT vip_level, balance FROM users WHERE id = $1", [userId]);
    const vipLevel = (ures.rows[0] && ures.rows[0].vip_level) ? ures.rows[0].vip_level : 'BASIC';
    const vipCfg = vipTiers[vipLevel] || vipTiers['BASIC'] || { cycle_size: 20, commission_rate: 0.03 };

    const vipCycleSize = parseInt(vipCfg.cycle_size, 10) || 20;
    const vipCommissionRate = parseFloat(vipCfg.commission_rate) || 0.03;
    const blockerArray = Array.isArray(globalBlockers) && globalBlockers.length ? globalBlockers : [12, 15, 18];

    // === 创建首个空 cycle ===
    const createCycle = await client.query(
      `INSERT INTO cycles (user_id, cycle_size, blocker_indexes, orders, status, created_at)
      VALUES ($1, $2, $3, $4, TRUE, NOW())
      RETURNING id`,
      [userId, vipCycleSize, blockerArray, []]
    );
    const cycleId = createCycle.rows[0].id;

    // === 获取任务模板 ===
    let tasksRes = await client.query(
      `SELECT id, product_name, product_description, image_url FROM tasks WHERE deleted_at IS NULL`
    );
    let availableTasks = tasksRes.rows;
    if (!availableTasks.length) {
      const placeholder = await client.query(
        `INSERT INTO tasks (product_name, product_description, image_url, created_at)
        VALUES ($1,$2,$3,NOW()) RETURNING id, product_name, product_description, image_url`,
        ['Demo Item', 'Auto-generated demo task', '']
      );
      availableTasks = [placeholder.rows[0]];
    }

    // === 生成 20 个订单 ===
    const baseBalance = parseFloat(ures.rows[0].balance) || 10;
    const orderIds = [];

    for (let i = 0; i < vipCycleSize; i++) {
      const t = availableTasks[Math.floor(Math.random() * availableTasks.length)]; // 随机任务
      const idx = i + 1;
      const isBlocker = blockerArray.includes(idx);

      let amount;
      if (isBlocker) {
        const mult = 1.10 + Math.random() * 0.10;
        amount = parseFloat((baseBalance * mult).toFixed(2));
        if (amount <= baseBalance) amount = parseFloat((baseBalance + 1).toFixed(2));
      } else {
        const pct = 0.90 + Math.random() * 0.05;
        amount = parseFloat((baseBalance * pct).toFixed(2));
      }

      if (amount < 50.00) {
        const randomExtra = Math.random() * 10;
        amount = parseFloat((50.00 + randomExtra).toFixed(2));
      }

      const commission = parseFloat((amount * vipCommissionRate).toFixed(2));

      const or = await client.query(
        `INSERT INTO orders (user_id, cycle_id, task_id, amount, commission, status, created_at)
        VALUES ($1,$2,$3,$4,$5,'PENDING',NOW()) RETURNING id`,
        [userId, cycleId, t.id, amount, commission]
      );

      orderIds.push(or.rows[0].id);
    }

    // === 更新 cycle 的 orders 字段 ===
    await client.query(
      `UPDATE cycles SET orders = $1 WHERE id = $2`,
      [orderIds, cycleId]
    );

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
      SELECT id, username, phone, email, gender, to_char(dob, 'YYYY-MM-DD') AS dob, balance, referral_code, credit_score, vip_level, profile_image, draw_ticket, wallet_address, can_do_task
      FROM users
      WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!userRes.rows.length)
      return res.status(500).json({ status: false, message: 'Server error' });

    const user = userRes.rows[0];

    // 当前激活 cycle
    const cycleRes = await client.query(`
      SELECT id, cycle_size, orders
      FROM cycles
      WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL
      ORDER BY id DESC LIMIT 1
    `, [userId]);

    // 当前进度
    let completion_ratio = '0/20';
    if (cycleRes.rows.length > 0) {
      const cycle = cycleRes.rows[0];
      const completedCountRes = await client.query(`
        SELECT COUNT(*) 
        FROM orders 
        WHERE cycle_id = $1 AND status = 'COMPLETED' AND deleted_at IS NULL
      `, [cycle.id]);

      const completedCount = parseInt(completedCountRes.rows[0].count, 10);
      completion_ratio = `${completedCount}/${cycle.cycle_size}`;
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
        profile_image: user.profile_image,
        referral_code: user.referral_code,
        credit_score: user.credit_score,
        vip_level: user.vip_level,
        balance: user.balance,
        daily_profit: daily_profit,
        tasks_completed: tasks_completed,
        completion_ratio: completion_ratio,
        draw_ticket: user.draw_ticket,
        wallet_address: user.wallet_address,
        can_do_task: user.can_do_task
      }
    });

  } catch (err) {
    console.error('/me error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/my-transactions', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const lang = req.headers['accept-language'] || 'en';

    const { types } = req.query;

    let conditions = [`user_id = $1`, `deleted_at IS NULL`];
    let params = [userId];
    let idx = params.length;

    if (types) {
      const arr = types.split(',').map(t => t.trim().toUpperCase());
      idx++;
      conditions.push(`UPPER(type) = ANY($${idx})`);
      params.push(arr);
    }

    const query = `
      SELECT id, amount, type, status, remark, created_at
      FROM transactions
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT 100
    `;

    const { rows } = await client.query(query, params);

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

  try {
    const query = `
      (
        SELECT o.id, o.amount, o.commission, o.status, o.created_at,
               t.product_name, t.image_url
        FROM orders o
        JOIN tasks t ON o.task_id = t.id
        WHERE o.user_id = $1 
          AND o.status = 'COMPLETED'
          AND o.deleted_at IS NULL
      )
      UNION ALL
      (
        SELECT o.id, o.amount, o.commission, o.status, o.created_at,
               t.product_name, t.image_url
        FROM orders o
        JOIN tasks t ON o.task_id = t.id
        WHERE o.user_id = $1 
          AND o.status = 'PENDING'
          AND o.deleted_at IS NULL
        ORDER BY o.created_at ASC
        LIMIT 1
      )
      ORDER BY created_at DESC
    `;

    const result = await client.query(query, [userId]);
    res.json({ status: true, data: result.rows });
  } catch (err) {
    console.error('GET /orders', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/orders', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  try {
    // 查找当前活跃周期
    const cr = await client.query(
      `SELECT id, orders, cycle_size, blocker_indexes
       FROM cycles 
       WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL 
       ORDER BY id DESC LIMIT 1`,
      [userId]
    );
    const cycle = cr.rows[0];

    // 若没有活跃周期
    if (!cycle) {
      return res.json({ status: false, message: 'No active cycle found. Please wait or contact support.' });
    }

    // 检查是否有 PENDING 订单
    const pending = await client.query(
      `SELECT o.id, o.amount, o.commission, t.product_name, t.product_description, t.image_url, o.created_at
       FROM orders o
       JOIN tasks t ON o.task_id = t.id
       WHERE o.user_id = $1 AND o.cycle_id = $2 AND o.status = 'PENDING' AND o.deleted_at IS NULL
       ORDER BY o.created_at ASC
       LIMIT 1`,
      [userId, cycle.id]
    );

    if (pending.rowCount > 0) {
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
    else
    {
      return res.json({
        status: false,
        message: t('tasks.allCompleted')
      });
    }
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
    // 1️⃣ 查订单 + cycle
    const { rows } = await client.query(`
      SELECT o.*, c.id AS cycle_id, c.orders, c.cycle_size
      FROM orders o
      JOIN cycles c ON o.cycle_id = c.id
      WHERE o.id = $1 AND o.user_id = $2 AND o.deleted_at IS NULL
    `, [orderId, userId]);
    if (!rows.length)
      return res.status(200).json({ status: false, message: t('error.orderNotFound') });

    const order = rows[0];
    const cycleId = order.cycle_id;
    const amount = parseFloat(order.amount);
    const commission = parseFloat(order.commission);

    // 2️⃣ 检查余额 + 扣款/返还
    const balRes = await client.query(`SELECT balance FROM users WHERE id = $1`, [userId]);
    if (!balRes.rows.length)
      return res.status(200).json({ status: false, message: t('error.userNotFound') });

    const balance = parseFloat(balRes.rows[0].balance);
    if (balance < amount)
      return res.status(200).json({ status: false, message: t('error.insufficientBalance') });

    // 扣款
    await client.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [amount, userId]);
    await client.query(`
      INSERT INTO transactions (user_id, amount, type, status, remark)
      VALUES ($1, $2, 'PURCHASE', 'APPROVED', $3)
    `, [userId, -amount, `#O_${orderId}_PURCHASE`]);

    // 发放用户自己佣金 + 本金
    const reward = amount + commission;
    await client.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [reward, userId]);
    await client.query(`
      INSERT INTO transactions (user_id, amount, type, status, remark)
      VALUES ($1, $2, 'COMMISSION', 'APPROVED', $3)
    `, [userId, reward, `#O_${orderId}_COMMISSION`]);

    // 💰 3️⃣ 发放上线奖励（佣金的25%）
    const ref = await client.query(`SELECT referred_by FROM users WHERE id = $1`, [userId]);
    if (ref.rows.length && ref.rows[0].referred_by) {
      const refId = ref.rows[0].referred_by;
      const refBonus = parseFloat((commission * 0.25).toFixed(2));

      await client.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [refBonus, refId]);
      await client.query(`
        INSERT INTO transactions (user_id, amount, type, status, remark)
        VALUES ($1, $2, 'REFERRAL_BONUS', 'APPROVED', $3)
      `, [refId, refBonus, `#O_${orderId}_REF_BONUS_FROM_${userId}`]);
    }

    // 4️⃣ 更新订单状态
    await client.query(`
      UPDATE orders 
      SET review_rating = $1, review_comment = $2, completed_at = NOW(), status = 'COMPLETED'
      WHERE id = $3
    `, [rating, comment, orderId]);
  
    res.json({ status: true, data: { reward: reward.toFixed(2) } });

  } catch (err) {
    console.error(`POST /orders/${orderId}/review`, err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/update-profile', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { walletAddress, securityPin } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  if (!securityPin)
    return res.status(200).json({ status: false, message: t('error.pinRequired') });

  try {
    const result = await client.query(`
      SELECT security_pin FROM users WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!result.rowCount || result.rows[0].security_pin !== securityPin)
      return res.status(200).json({ status: false, message: t('error.invalidPin') });

    await client.query(`
      UPDATE users SET wallet_address = $1, updated_at = NOW() WHERE id = $2
    `, [walletAddress, userId]);

    res.json({ status: true });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ status: false, message: "Server Error"});
  }
});

app.post('/update-profile-image', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { profile_image } = req.body;

  try {
    await client.query(`UPDATE users SET profile_image = $1 WHERE id = $2`, [profile_image, userId]);

    res.json({ status: true});
  } catch (err) {
    console.error('Update profile image error:', err);
    res.status(500).json({ status: false, message: "Server Error" });
  }
});

app.post('/withdraw', verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const { amount, pin } = req.body;
  const lang = req.headers['accept-language'] || 'en';
  const t = (key) => languages[lang]?.[key] || languages['en'][key] || key;

  if (!amount || isNaN(amount) || amount <= 0)
    return res.status(200).json({ status: false, message: t('error.invalidAmount') });

  if (!/^\d{6}$/.test(pin))
    return res.status(200).json({ status: false, message: t('error.invalidPin') });

  try {
    // 获取用户资料（包含 balance 和 security_pin）
    const userRes = await client.query(`
      SELECT balance, security_pin FROM users 
      WHERE id = $1 AND deleted_at IS NULL
    `, [userId]);

    if (!userRes.rows.length)
      return res.status(200).json({ status: false, message: t('error.userNotFound') });

    const user = userRes.rows[0];
    const balance = parseFloat(user.balance);

    // 验证 PIN 是否匹配
    if (user.security_pin !== pin)
      return res.status(200).json({ status: false, message: t('error.incorrectPin') });

    // 验证余额
    if (balance < amount)
      return res.status(200).json({ status: false, message: t('error.insufficientBalance') });

    // 保留最少 100 USD
    if (balance - amount < 100)
      return res.status(200).json({ status: false, message: t('error.minBalance') });

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
    res.status(500).json({ status: false, message: 'Failed to fetch team' });
  }
});

app.get('/my-loans', verifyToken, async (req, res) => {
  try {
    const loansResult = await client.query(
      'SELECT id, amount, term, interest_rate, status, remark, created_at FROM loan_requests WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );

    const configResult = await client.query(
      'SELECT value FROM config WHERE key = $1',
      ['vip_tiers']
    );

    const vipTiers = configResult.rows.length > 0 ? JSON.parse(configResult.rows[0].value) : null;

    return res.json({
      data: loansResult.rows,
      vipTiers
    });
  } catch (err) {
    console.error('Error fetching my loans:', err);
    return res.status(500).json({ status: false, error: 'Failed to fetch loans' });
  }
});

app.post('/loan-requests', verifyToken, async (req, res) => {
  const { amount, pin, term, remark } = req.body;

  if (!amount || isNaN(amount) || amount <= 0) {
    return res.status(200).json({ status: false, message: 'Invalid loan amount' });
  }

  if (!pin) {
    return res.status(200).json({ status: false, message: 'PIN is required' });
  }

  try {
    // 从 users 表检查 PIN
    const userResult = await client.query(
      'SELECT security_pin FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (!userResult.rows.length || userResult.rows[0].security_pin !== pin) {
      return res.status(200).json({ status: false, message: 'Incorrect PIN' });
    }

    // 计算利率，可以用一个 map
    const termRates = { 3: 2, 7: 3, 15: 5, 30: 8 };
    const interest_rate = termRates[term] || 2;

    // 插入 loan
    const insertResult = await client.query(
      'INSERT INTO loan_requests (user_id, amount, term, interest_rate, remark) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, amount, term, interest_rate, remark || null]
    );

    // 取 VIP 配置
    const configResult = await client.query(
      'SELECT value FROM config WHERE key = $1',
      ['vip_tiers']
    );
    const vipTiers = configResult.rows.length > 0 ? JSON.parse(configResult.rows[0].value) : null;

    return res.status(200).json({
      status: true,
      message: 'Loan request submitted',
      data: insertResult.rows[0],
      vipTiers
    });

  } catch (err) {
    console.error('Error creating loan request:', err);
    return res.status(500).json({ status: false, message: 'Failed to create loan request' });
  }
});

app.get('/checkin', verifyToken, async (req, res) => {
  const t = key => (req && typeof req.t === 'function' ? req.t(key) : key);
  const userId = req.user && req.user.userId;
  if (!userId) return res.status(200).json({ status: false, message: t('error.invalidUser') });

  try {
    const now = new Date();
    const yyyy = now.getFullYear();
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const dd = String(now.getDate()).padStart(2, '0');
    const todayStr = `${yyyy}-${mm}-${dd}`;

    // checked days in current month
    const month = now.getMonth() + 1;
    const year = yyyy;
    const chRes = await client.query(
      `SELECT EXTRACT(DAY FROM checkin_date) AS day
       FROM checkin
       WHERE user_id = $1
         AND EXTRACT(YEAR FROM checkin_date) = $2
         AND EXTRACT(MONTH FROM checkin_date) = $3
       ORDER BY day`,
      [userId, year, month]
    );
    const checkedDays = chRes.rows.map(r => parseInt(r.day, 10));

    // is checked today?
    const chkTodayRes = await client.query(
      `SELECT 1 FROM checkin WHERE user_id = $1 AND checkin_date = $2 LIMIT 1`,
      [userId, todayStr]
    );
    const todayChecked = chkTodayRes.rowCount > 0;

    // number of cycles finished today
    const cycleRes = await client.query(
      `SELECT COUNT(*)::int AS cnt
       FROM cycles
       WHERE user_id = $1
         AND finished_at::date = $2
         AND deleted_at IS NULL`,
      [userId, todayStr]
    );
    const todayCycles = parseInt(cycleRes.rows[0].cnt, 10) || 0;
    const requiredCycles = 2;

    return res.status(200).json({
      status: true,
      message: '',
      data: { checkedDays, todayChecked, todayCycles, requiredCycles }
    });
  } catch (err) {
    console.error('GET /checkin error', err);
    return res.status(500).json({ status: false, message: t('error.internalServer') });
  }
});

app.post('/checkin', verifyToken, async (req, res) => {
  const t = key => (req && typeof req.t === 'function' ? req.t(key) : key);
  const userId = req.user && req.user.userId;
  if (!userId) return res.status(200).json({ status: false, message: t('error.invalidUser') });

  try {
    const now = new Date();
    const yyyy = now.getFullYear();
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const dd = String(now.getDate()).padStart(2, '0');
    const todayStr = `${yyyy}-${mm}-${dd}`;

    // check cycles completed today
    const cycleRes = await client.query(
      `SELECT COUNT(*)::int AS cnt
       FROM cycles
       WHERE user_id = $1
         AND finished_at::date = $2
         AND deleted_at IS NULL`,
      [userId, todayStr]
    );
    const todayCycles = parseInt(cycleRes.rows[0].cnt, 10) || 0;
    const requiredCycles = 2;
    if (todayCycles < requiredCycles) {
      return res.status(200).json({ status: false, message: t('profile.checkInStatus.need2cycle') });
    }

    // already checked in?
    const chkRes = await client.query(
      `SELECT 1 FROM checkin WHERE user_id = $1 AND checkin_date = $2 LIMIT 1`,
      [userId, todayStr]
    );
    if (chkRes.rowCount > 0) {
      return res.status(200).json({ status: false, message: t('profile.checkInStatus.allDone') });
    }

    // insert check-in
    await client.query(
      `INSERT INTO checkin (user_id, checkin_date, created_at)
       VALUES ($1, $2, NOW())`,
      [userId, todayStr]
    );

    return res.status(200).json({ status: true, message: t('profile.checkInStatus.success') });
  } catch (err) {
    console.error('POST /checkin error', err);
    return res.status(500).json({ status: false, message: t('error.internalServer') });
  }
});

app.get('/lucky_draw_rates', verifyToken, async (req, res) => {
  try {
    const userRes = await client.query(
      'SELECT lucky_draw_setting FROM users WHERE id=$1',
      [req.user.userId]
    );

    if (!userRes.rows.length)
      return res.status(200).json({ status: false, message: 'User not found' });

    const settingRaw = userRes.rows[0].lucky_draw_setting || '[]';
    let prizes = [];
    try {
      prizes = JSON.parse(settingRaw);
    } catch {
      prizes = [];
    }

    return res.status(200).json({ status: true, data: prizes });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: 'Failed to load prizes' });
  }
});

app.post('/lucky_draw_spin', verifyToken, async (req, res) => {
  try {
    const userRes = await client.query(
      'SELECT draw_ticket, lucky_draw_setting FROM users WHERE id=$1',
      [req.user.userId]
    );

    if (!userRes.rows.length)
      return res.status(200).json({ status: false, message: 'User not found' });

    const { draw_ticket, lucky_draw_setting } = userRes.rows[0];
    if (draw_ticket < 1)
      return res.status(200).json({ status: false, message: 'No draw tickets left' });

    let prizes = [];
    try {
      prizes = JSON.parse(lucky_draw_setting || '[]');
    } catch {
      prizes = [];
    }

    // 构建抽奖箱
    const box = [];
    prizes.forEach(p => {
      const qty = Math.max(0, Math.floor(p.rate));
      for (let i = 0; i < qty; i++) box.push(p);
    });

    if (box.length === 0)
      return res.status(200).json({ status: false, message: 'No prizes available' });

    // 抽取奖品
    const prize = box[Math.floor(Math.random() * box.length)];

    // 扣除抽奖券
    await client.query(
      'UPDATE users SET draw_ticket = draw_ticket - 1 WHERE id=$1',
      [req.user.userId]
    );

    // 记录中奖
    await client.query(
      'INSERT INTO draw_records (user_id, prize_name, created_at) VALUES ($1, $2, NOW())',
      [req.user.userId, prize.name]
    );

    return res.status(200).json({ status: true, data: prize.name });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: 'Spin failed' });
  }
});

// Admin
app.get('/users', verifyAdminToken, async (req, res) => {
  try {
    const { page, limit, search } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 50;
    const offset = (pageNum - 1) * limitNum;
    const hasSearch = search && search.trim() !== '';

    // 查询总数
    let countQuery = 'SELECT COUNT(*) FROM users WHERE user_type = 2 AND deleted_at IS NULL';
    const countParams = [];
    if (hasSearch) {
      countQuery += ' AND (username ILIKE $1 OR phone ILIKE $1)';
      countParams.push(`%${search}%`);
    }
    const countRes = await client.query(countQuery, countParams);
    const totalUsers = parseInt(countRes.rows[0].count, 10);
    const totalPages = Math.ceil(totalUsers / limitNum);

    // 查询数据
    let usersQuery = `
      SELECT id, username, password, security_pin, phone, wallet_address, email, country, gender,
        TO_CHAR(dob, 'YYYY-MM-DD') AS dob, balance, draw_ticket, referral_code, referred_by,
        status, can_withdraw, can_do_task, user_type, vip_level, credit_score, last_login, created_at, is_demo, lucky_draw_setting
      FROM users
      WHERE user_type = 2 AND deleted_at IS NULL
    `;
    const params = [];
    if (hasSearch) {
      usersQuery += ' AND (username ILIKE $1 OR phone ILIKE $1)';
      params.push(`%${search}%`);
    }
    usersQuery += ` ORDER BY id ASC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limitNum, offset);

    const usersRes = await client.query(usersQuery, params);
    const users = [];

    for (const user of usersRes.rows) {
      const cycleRes = await client.query(`
        SELECT id, cycle_size, orders
        FROM cycles
        WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL
        ORDER BY id DESC LIMIT 1
      `, [user.id]);

      let completion_ratio = '0/0';
      let balance_gap = 0;

      if (cycleRes.rows.length > 0) {
        const cycle = cycleRes.rows[0];
        const orderIds = Array.isArray(cycle.orders) ? cycle.orders : [];

        let completedCount = 0;
        let latestPendingAmount = 0;

        if (orderIds.length > 0) {
          const ordersRes = await client.query(`
            SELECT id, amount, status
            FROM orders
            WHERE id = ANY($1::int[])
            ORDER BY id ASC
          `, [orderIds]);

          const completedOrders = ordersRes.rows.filter(o => o.status === 'COMPLETED');
          completedCount = completedOrders.length;

          const pendingOrder = ordersRes.rows.find(o => o.status !== 'COMPLETED');
          if (pendingOrder) latestPendingAmount = Number(pendingOrder.amount) || 0;
        }

        completion_ratio = `${completedCount}/${cycle.cycle_size}`;
        const diff = user.balance - latestPendingAmount;
        balance_gap = diff < 0 ? Number(diff.toFixed(2)) : 0;
      }

      users.push({ ...user, completion_ratio, balance_gap });
    }

    res.json({
      status: true,
      data: users,
      pagination: {
        page: pageNum,
        totalPages,
        totalUsers,
        limit: limitNum
      }
    });
  } catch (err) {
    console.error('Error fetching admin users:', err);
    res.status(500).json({ status: false, error: 'Failed to fetch users' });
  }
});

app.get('/all-users-list', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(`
      SELECT id, username 
      FROM users 
      WHERE user_type = 2 AND deleted_at IS NULL 
      ORDER BY username ASC
    `);

    res.json({
      status: true,
      data: result.rows
    });
  } catch (err) {
    console.error('Error fetching all users list:', err);
    res.status(500).json({ status: false, error: 'Failed' });
  }
});

app.post('/create-demo', verifyToken, async (req, res) => {
  try {
    const { username, password, referred_by, balance, commission_rate } = req.body;
    if (!username || !password)
      return res.status(200).json({ status: false, message: '用户名与密码必填' });

    // 检查用户名是否重复
    const existCheck = await client.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existCheck.rowCount > 0)
      return res.status(200).json({ status: false, message: '该用户名已存在' });

    // 验证 balance 与 commission_rate 范围
    const initialBalance = parseFloat(balance);
    const commissionRate = parseFloat(commission_rate);
    if (isNaN(initialBalance) || initialBalance < 0)
      return res.status(400).json({ status: false, message: '余额必须为非负数字' });
    if (isNaN(commissionRate) || commissionRate < 0 || commissionRate > 100)
      return res.status(400).json({ status: false, message: '佣金比例必须在 0 - 100 之间' });

    const security_pin = Math.floor(1000 + Math.random() * 9000).toString();
    const vipLevel = 'BASIC';

    // 获取 blocker 配置
    const cfgRes = await client.query("SELECT key, value FROM config WHERE key = 'blocker_indexes'");
    const cfgMap = Object.fromEntries(cfgRes.rows.map(r => [r.key, r.value || '']));
    const blockerIndexes = (cfgMap.blocker_indexes || '')
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !Number.isNaN(n));

    // 生成唯一推荐码
    let selfReferralCode;
    while (true) {
      const tempCode = generateReferralCode();
      const check = await client.query('SELECT 1 FROM users WHERE referral_code = $1', [tempCode]);
      if (check.rowCount === 0) {
        selfReferralCode = tempCode;
        break;
      }
    }

    // 插入用户
    const userRes = await client.query(
      `INSERT INTO users
         (username, password, security_pin, is_demo, referral_code, referred_by, user_type, vip_level, balance,
          can_withdraw, can_do_task, status, created_at, phone)
       VALUES ($1, $2, $3, TRUE, $4, $5, 2, $6, $7, FALSE, FALSE, FALSE, CURRENT_TIMESTAMP, $8)
       RETURNING id, balance`,
      [username, password, security_pin, selfReferralCode, referred_by || null, vipLevel, initialBalance, 'lzRQXWY4QzVsor1g5EtBhGUHXInd9ptH']
    );

    const userId = userRes.rows[0].id;
    let baseBalance = parseFloat(userRes.rows[0].balance);
    const cycleSize = 20;
    const blockerArray = blockerIndexes.length ? blockerIndexes : null;

    // 创建 cycle
    const cycleRes = await client.query(
      `INSERT INTO cycles (user_id, cycle_size, blocker_indexes, orders, status, created_at)
       VALUES ($1, $2, $3, '{}', TRUE, NOW())
       RETURNING id, blocker_indexes`,
      [userId, cycleSize, blockerArray]
    );

    const cycleId = cycleRes.rows[0].id;
    const usedBlockers = Array.isArray(cycleRes.rows[0].blocker_indexes)
      ? cycleRes.rows[0].blocker_indexes
      : (blockerArray || []);

    // 获取任务模板
    let tasksRes = await client.query(
      `SELECT id, product_name, product_description, image_url FROM tasks WHERE deleted_at IS NULL ORDER BY id ASC LIMIT $1`,
      [cycleSize]
    );
    if (tasksRes.rowCount === 0) {
      const placeholder = await client.query(
        `INSERT INTO tasks (product_name, product_description, image_url, created_at)
         VALUES ($1,$2,$3,NOW()) RETURNING id, product_name, product_description, image_url`,
        ['Demo Item', 'Auto-generated demo task', '']
      );
      tasksRes = { rows: [placeholder.rows[0]] };
    }

    const availableTasks = tasksRes.rows;
    const orderIds = [];

    // 生成 20 个订单
    const randomIndexes = Array.from({ length: cycleSize }, (_, i) => i + 1).sort(() => Math.random() - 0.5);

    for (const idx of randomIndexes) {
      const t = availableTasks[Math.floor(Math.random() * availableTasks.length)];
      const isBlocker = Array.isArray(usedBlockers) && usedBlockers.includes(idx);

      let amount;
      if (isBlocker) {
        const mult = 1.10 + Math.random() * 0.10;
        amount = parseFloat((baseBalance * mult).toFixed(2));
        if (amount <= baseBalance) amount = parseFloat((baseBalance + 1).toFixed(2));
        if (baseBalance <= 0) amount = 1.00;
      } else {
        const pct = 0.90 + Math.random() * 0.05;
        amount = parseFloat((baseBalance * pct).toFixed(2));
        if (amount <= 0) amount = 1.00;
      }

      const commission = parseFloat((amount * commissionRate / 100).toFixed(2));

      const or = await client.query(
        `INSERT INTO orders (user_id, cycle_id, task_id, amount, commission, status, created_at)
         VALUES ($1,$2,$3,$4,$5,'PENDING',NOW()) RETURNING id`,
        [userId, cycleId, t.id, amount, commission]
      );

      orderIds.push(or.rows[0].id);
    }

    await client.query(
      `UPDATE cycles SET orders = $1 WHERE id = $2`,
      [orderIds, cycleId]
    );

    return res.json({
      status: true,
      data: { username, password }
    });
  } catch (err) {
    console.error('Error creating demo account:', err);
    return res.status(500).json({ status: false, message: '创建测试账号失败' });
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
    res.status(500).json({ status: false, message:'Server Error' });
  }
});

app.post('/user/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { password, security_pin, phone, email, gender, dob, vip_level, credit_score } = req.body;

  if (!id) return res.status(200).json({ status: false, message: 'Invalid ID' });

  try {
    const result = await client.query(
      `UPDATE users 
       SET password=$1, security_pin=$2, phone=$3, email=$4, gender=$5, dob=$6, vip_level=$7, credit_score=$8 
       WHERE id=$9`,
      [password, security_pin, phone, email, gender, dob, vip_level, credit_score, id]
    );

    if (result.rowCount === 0) {
      return res.status(200).json({ status: false, message: 'User not found' });
    }

    res.json({ status: true, message: 'User updated' });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.patch('/user/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const allowedFields = ['status', 'can_withdraw', 'can_do_task'];

  // 找出 body 里允许更新的字段
  const updates = Object.entries(req.body).filter(([key, val]) => 
    allowedFields.includes(key) && typeof val === 'boolean'
  );

  if (updates.length === 0) {
    return res.status(200).json({ status: false, message: 'No valid fields to update' });
  }

  try {
    // 动态拼 update 语句
    const setClause = updates.map(([key], i) => `${key}=$${i + 1}`).join(', ');
    const values = updates.map(([_, val]) => val);
    values.push(id);

    const result = await client.query(
      `UPDATE users SET ${setClause} WHERE id=$${values.length}`,
      values
    );

    if (result.rowCount === 0) {
      return res.status(200).json({ status: false, message: t('error.userNotFound') });
    }

    res.json({ message: 'User updated' });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.delete('/user/:id', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await client.query(`
      UPDATE users
      SET deleted_at = NOW()
      WHERE id = $1 AND deleted_at IS NULL
      RETURNING id
    `, [req.params.id]);

    if (!rows.length) {
      return res.status(200).json({ status: false, message: 'Not found or already deleted' });
    }

    res.json({ status: true, data: { id: rows[0].id } });
  } catch (err) {
    console.error(`DELETE /user/${req.params.id}`, err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/tasks', verifyAdminToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;

  try {
    const dataQuery = `
      SELECT * FROM tasks
      WHERE deleted_at IS NULL
      ORDER BY id
      LIMIT $1 OFFSET $2
    `;
    const countQuery = `
      SELECT COUNT(*) FROM tasks WHERE deleted_at IS NULL
    `;

    const [dataResult, countResult] = await Promise.all([
      client.query(dataQuery, [limit, offset]),
      client.query(countQuery)
    ]);

    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);

    res.json({
      status: true,
      data: dataResult.rows,
      page,
      totalPages,
      total
    });
  } catch (err) {
    res.status(500).json({ status: false, message: 'Fetch tasks failed' });
  }
});

app.get('/tasks/:id', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(
      'SELECT * FROM tasks WHERE id = $1 AND deleted_at IS NULL',
      [req.params.id]
    );
    if (!result.rows.length) return res.status(200).json({ status: false, message: 'Task not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ status: false, message: 'Fetch task failed' });
  }
});

app.post('/tasks', verifyAdminToken, async (req, res) => {
  const { productName, imageUrl, taskDescription} = req.body;
  try {
    const result = await client.query(
      `INSERT INTO tasks (product_name, image_url, product_description)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [productName, imageUrl, taskDescription]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'Create task failed' });
  }
});

app.put('/tasks/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { productName, imageUrl, taskDescription } = req.body;
  try {
    const result = await client.query(
      `UPDATE tasks 
       SET product_name = $1, 
           image_url = $2, 
           product_description = $3,
       WHERE id = $4 AND deleted_at IS NULL 
       RETURNING *`,
      [productName, imageUrl, taskDescription, id]
    );
    if (!result.rows.length) return res.status(200).json({ status: false, message: 'Task not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'Update failed' });
  }
});

app.delete('/tasks/:id', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(
      `UPDATE tasks SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING id`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(200).json({ status: false, message: 'Task not found or already deleted' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ status: false, message: 'Delete failed' });
  }
});

app.put('/orders/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, commission_rate } = req.body;

    const newAmount = parseFloat(amount);
    const rate = parseFloat(commission_rate) / 100;

    const currentRes = await client.query('SELECT amount, cycle_id FROM orders WHERE id = $1', [id]);
    if (currentRes.rowCount === 0) return res.json({ status: false, message: 'Order not found' });

    const oldAmount = parseFloat(currentRes.rows[0].amount);
    const cycleId = currentRes.rows[0].cycle_id;
    const delta = newAmount - oldAmount;

    const result = await client.query(`
      UPDATE orders 
      SET amount = $1::numeric, 
        commission = ($1::numeric * $2::numeric)
      WHERE id = $3 AND deleted_at IS NULL
      RETURNING *;
    `, [newAmount, rate, id]);

    if (delta > 0) {
      await client.query(`
        UPDATE orders 
        SET amount = amount + $1::numeric,
          commission = (amount + ($1::numeric * 1.05)) * $2::numeric
        WHERE cycle_id = $3 AND id > $4 AND deleted_at IS NULL
      `, [delta, rate, cycleId, id]);
    }

    res.json({ status: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ status: false, error: 'Update failed' });
  }
});

app.delete('/orders/:id', verifyAdminToken, async (req, res) => {
  const orderId = parseInt(req.params.id, 10);

  try {
    // soft delete
    const upd = await client.query(`
      UPDATE orders
      SET deleted_at = NOW()
      WHERE id = $1
      RETURNING cycle_id
    `, [orderId]);

    if (!upd.rowCount) return res.status(200).json({ status: false, message: 'Order not found' });

    const cycleId = upd.rows[0].cycle_id;

    // 从 cycle.orders 里移除
    await client.query(`
      UPDATE cycles
      SET orders = array_remove(orders, $1)
      WHERE id = $2
    `, [orderId, cycleId]);

    res.json({ status: true });
  } catch (err) {
    console.error("DELETE /orders/:id error:", err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/cycles', verifyAdminToken, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(200).json({ status: false, message: 'Missing userId' });
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
        o.created_at ASC
    `, [activeCycle.id]);

    activeCycle.orders = ordersResult.rows;

    res.json({ status: true, data: [activeCycle] });

  } catch (err) {
    console.error('Error fetching cycles:', err);
    res.status(500).json({ status: false, error: 'Fetch failed' });
  }
});

app.post('/cycles/:id/orders', verifyAdminToken, async (req, res) => {
  const cycleId = parseInt(req.params.id, 10);
  const { productId } = req.body;

  if (!productId) return res.status(200).json({ status: false, message: 'productId required' });

  try {
    // 查 cycle
    const cRes = await client.query(`
      SELECT user_id FROM cycles WHERE id=$1 AND deleted_at IS NULL
    `, [cycleId]);
    if (!cRes.rowCount) return res.status(200).json({ status: false, message: 'Cycle not found' });
    const userId = cRes.rows[0].user_id;

    // 查 product
    const pRes = await client.query(`
      SELECT product_price FROM tasks WHERE id=$1 AND deleted_at IS NULL
    `, [productId]);
    if (!pRes.rowCount) return res.status(200).json({ status: false, message: 'Product not found' });
    const amount = parseFloat(pRes.rows[0].product_price);

    // 查 config 取 commission_rate
    const cfgRes = await client.query(`
      SELECT value FROM config WHERE key='commission_rate'
    `);
    const commissionRate = parseFloat(cfgRes.rows[0]?.value || 0);
    const commission = parseFloat((amount * commissionRate).toFixed(2));

    // 插入 order
    const oRes = await client.query(`
      INSERT INTO orders (user_id, cycle_id, task_id, amount, commission)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
    `, [userId, cycleId, productId, amount, commission]);

    const orderId = oRes.rows[0].id;

    // 把 order id push 进 cycle.orders
    await client.query(`
      UPDATE cycles
      SET orders = array_append(orders, $1)
      WHERE id = $2
    `, [orderId, cycleId]);

    res.json({ status: true, orderId });
  } catch (err) {
    console.error("POST /cycles/:id/orders error:", err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.post('/cycle/reset', verifyAdminToken, async (req, res) => {
  const userId = req.body.userId;
  if (!userId) return res.status(200).json({ status: false, message: 'Missing userId' });

  try {
    // 1️⃣ 用户信息
    const userRes = await client.query(
      `SELECT id, vip_level, balance FROM users WHERE id = $1 LIMIT 1`,
      [userId]
    );
    if (userRes.rowCount === 0) return res.json({ status: false, message: 'User not found' });
    const user = userRes.rows[0];
    const baseBalance = parseFloat(user.balance) || 0;

    // 2️⃣ vip_tiers
    const cfgVip = await client.query(`SELECT value FROM config WHERE key = 'vip_tiers' LIMIT 1`);
    if (cfgVip.rowCount === 0) return res.json({ status: false, message: 'vip_tiers not found' });

    const vipTiers = JSON.parse(cfgVip.rows[0].value);
    const tierKey = Object.keys(vipTiers).find(k => k.toUpperCase() === user.vip_level.toUpperCase());
    const tierCfg = vipTiers[tierKey] || vipTiers['BASIC'];
    const cycleSize = tierCfg.cycle_size || 20;
    const commissionRate = parseFloat(tierCfg.commission_rate) || 0.03;

    // 3️⃣ blocker_indexes
    const cfgBlock = await client.query(`SELECT value FROM config WHERE key = 'blocker_indexes' LIMIT 1`);
    const blockerArray = cfgBlock.rowCount > 0
      ? cfgBlock.rows[0].value.split(',').map(v => parseInt(v.trim())).filter(v => !isNaN(v))
      : [12, 15, 18];

    // 4️⃣ 关闭旧 cycle
    await client.query(
      `UPDATE cycles SET status = FALSE, finished_at = NOW()
       WHERE user_id = $1 AND status = TRUE AND deleted_at IS NULL`,
      [userId]
    );

    // 5️⃣ 创建新 cycle
    const cycleRes = await client.query(
      `INSERT INTO cycles (user_id, cycle_size, blocker_indexes, orders, status, created_at)
       VALUES ($1, $2, $3, '{}', TRUE, NOW())
       RETURNING id, blocker_indexes`,
      [userId, cycleSize, blockerArray]
    );

    const cycleId = cycleRes.rows[0].id;
    const usedBlockers = Array.isArray(cycleRes.rows[0].blocker_indexes)
      ? cycleRes.rows[0].blocker_indexes
      : blockerArray;

    // 6️⃣ 获取任务模板
    let tasksRes = await client.query(
      `SELECT id, product_name, product_description, image_url
       FROM tasks WHERE deleted_at IS NULL ORDER BY id ASC LIMIT $1`,
      [cycleSize]
    );
    if (tasksRes.rowCount === 0) {
      const placeholder = await client.query(
        `INSERT INTO tasks (product_name, product_description, image_url, created_at)
         VALUES ($1,$2,$3,NOW()) RETURNING id, product_name, product_description, image_url`,
        ['Demo Item', 'Auto-generated demo task', '']
      );
      tasksRes = { rows: [placeholder.rows[0]] };
    }

    const availableTasks = tasksRes.rows;
    const orderIds = [];

    // 7️⃣ 生成订单（随机抽选任务）
    for (let i = 0; i < cycleSize; i++) {
      // 随机取一个任务
      const t = availableTasks[Math.floor(Math.random() * availableTasks.length)];

      const idx = i + 1;
      const isBlocker = usedBlockers.includes(idx);

      let amount;
      if (isBlocker) {
        const mult = 1.10 + Math.random() * 0.10;
        amount = parseFloat((baseBalance * mult).toFixed(2));
        if (amount <= baseBalance) amount = parseFloat((baseBalance + 1).toFixed(2));
        if (baseBalance <= 0) amount = 1.00;
      } else {
        const pct = 0.90 + Math.random() * 0.05;
        amount = parseFloat((baseBalance * pct).toFixed(2));
        if (amount <= 0) amount = 1.00;
      }

      const commission = parseFloat((amount * commissionRate).toFixed(2));

      const or = await client.query(
        `INSERT INTO orders (user_id, cycle_id, task_id, amount, commission, status, created_at)
        VALUES ($1,$2,$3,$4,$5,'PENDING',NOW()) RETURNING id`,
        [userId, cycleId, t.id, amount, commission]
      );
      orderIds.push(or.rows[0].id);
    }

    // 8️⃣ 更新 cycle orders
    await client.query(`UPDATE cycles SET orders = $1 WHERE id = $2`, [orderIds, cycleId]);

    return res.json({ status: true });

  } catch (err) {
    console.error('POST /cycle/reset error:', err);
    return res.status(500).json({ status: false, error: 'Reset failed' });
  }
});

app.get('/transactions', verifyAdminToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const offset = (page - 1) * limit;

    const whereClause = search
      ? `WHERE t.deleted_at IS NULL AND u.username ILIKE $3`
      : `WHERE t.deleted_at IS NULL`;

    const params = search
      ? [limit, offset, `%${search}%`]
      : [limit, offset];

    const { rows } = await client.query(
      `
      SELECT t.id, u.username, t.amount, t.type, t.status, t.remark, t.created_at
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      ${whereClause}
      ORDER BY t.created_at DESC
      LIMIT $1 OFFSET $2
      `,
      params
    );

    const totalRes = await client.query(
      `
      SELECT COUNT(*) AS total
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      ${search ? `WHERE t.deleted_at IS NULL AND u.username ILIKE $1` : `WHERE t.deleted_at IS NULL`}
      `,
      search ? [`%${search}%`] : []
    );

    const total = parseInt(totalRes.rows[0].total, 10);
    const totalPages = Math.ceil(total / limit);

    res.json({
      status: true,
      data: rows,
      pagination: { page: Number(page), totalPages, total }
    });
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
    return res.status(200).json({ status: false, message: 'Invalid status' });
  }

  try {
    // 1. 【修复核心】删除了 RETURNING 里的 cycle_id
    // 之前报错就是因为数据库 transactions 表里根本没这个字段
    const upd = await client.query(`
      UPDATE transactions
      SET status = $1
      WHERE id = $2 AND deleted_at IS NULL
      RETURNING id, user_id, amount, type
    `, [newStat, txId]);

    if (!upd.rowCount) {
      return res.status(200).json({ status: false, message: 'Transaction not found' });
    }

    const { user_id, amount, type } = upd.rows[0];

    // 2. 如果是 APPROVED (通过)
    if (newStat === 'APPROVED') {
      const plusTypes = ['DEPOSIT', 'COMMISSION'];
      // DEPOSIT (充值) 会在这里给用户加钱
      const delta = plusTypes.includes(type.toUpperCase()) ? amount : -amount;

      // 更新余额
      await client.query(`
        UPDATE users
        SET balance = balance + $1
        WHERE id = $2
      `, [delta, user_id]);

      // 3. 只有当类型是 COMMISSION 时，才去处理关闭周期(Cycle)的逻辑
      if (type.toUpperCase() === 'COMMISSION') {
        
        // 手动查找当前正在进行的 Cycle (而不是从 transaction 表里拿)
        const activeCycleRes = await client.query(`
            SELECT id FROM cycles WHERE user_id = $1 AND status = TRUE LIMIT 1
        `, [user_id]);

        if (activeCycleRes.rows.length > 0) {
            const cycle_id = activeCycleRes.rows[0].id;
            
            // 关闭旧 cycle
            await client.query(`
              UPDATE cycles 
              SET status = FALSE, finished_at = NOW() 
              WHERE id = $1
            `, [cycle_id]);

            // 处理下线分佣 (逻辑保持不变)
            const downlineRate = 0.25;
            const ures = await client.query(`SELECT referred_by FROM users WHERE id = $1`, [user_id]);
            const referredBy = ures.rows[0] ? ures.rows[0].referred_by : null;

            if (referredBy) {
              const userRes = await client.query(
                `SELECT id, username FROM users WHERE username = $1`,
                [referredBy]
              );
              const referer = userRes.rows[0];
              
              if (referer) {
                const refererShare = parseFloat((amount * downlineRate).toFixed(2));
                if (refererShare > 0) {
                  const remark = `Downline: (ID:${user_id}) - #C_${cycle_id}`;
                  await client.query(`
                    INSERT INTO transactions (user_id, type, amount, status, remark)
                    VALUES ($1, 'COMMISSION', $2, 'APPROVED', $3)
                  `, [referer.id, refererShare, remark]);
                }
              }
            }
        }

        // 开启新 Cycle (逻辑保持不变)
        const configRes = await client.query(`
          SELECT key, value FROM config WHERE key IN ('cycle_size', 'blocker_indexes')
        `);
        const cfgMap = Object.fromEntries(configRes.rows.map(r => [r.key, r.value]));

        const newSize = parseInt(cfgMap['cycle_size'], 10) || 20;
        const blockerIndexes = (cfgMap['blocker_indexes'] || '')
          .split(',')
          .map(n => parseInt(n.trim(), 10))
          .filter(n => !isNaN(n));

        await client.query(`
          INSERT INTO cycles (user_id, cycle_size, blocker_indexes, orders, status, created_at) 
          VALUES ($1, $2, $3, '{}', TRUE, NOW())
        `, [user_id, newSize, blockerIndexes]);
      }
    }

    // 如果是提现 + 被拒绝 => 把钱退回余额
    if (type.toUpperCase() === 'WITHDRAWAL' && newStat === 'REJECTED') {
      await client.query(`
        UPDATE users
        SET balance = balance + $1
        WHERE id = $2
      `, [Math.abs(amount), user_id]);
    }

    res.json({ status: true, data: { id: txId, status: newStat } });

  } catch (err) {
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
    if (!rows.length) return res.status(200).json({ status: false, message: 'Not found or already deleted' });
    res.json({ status: true, data: { id: rows[0].id } });
  } catch (err) {
    console.error(`DELETE /transactions/${req.params.id}`, err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.get('/loan-requests', verifyAdminToken, async (req, res) => {
  try {
    const result = await client.query(`
      SELECT 
        l.id, l.user_id, u.username, l.amount, l.status, l.remark, l.created_at
      FROM loan_requests l
      JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC
    `);
    return res.json({ status: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching loan requests:', err);
    return res.status(500).json({ status: false, message: 'Failed to fetch loan requests' });
  }
});

app.patch('/loan-requests/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['APPROVED', 'REJECTED'].includes(status)) {
    return res.status(200).json({ status: false, message: 'Invalid status' });
  }

  try {
    // 更新 loan 状态
    const result = await client.query(
      'UPDATE loan_requests SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );

    if (result.rowCount === 0) {
      return res.status(200).json({ status: false, message: 'Loan request not found' });
    }

    const loan = result.rows[0];

    if (status === 'APPROVED') {
      await client.query(
        'UPDATE users SET balance = balance + $1 WHERE id = $2',
        [loan.amount, loan.user_id]
      );

      await client.query(
        `INSERT INTO transactions (user_id, amount, type, remark, created_at)
         VALUES ($1, $2, 'DEPOSIT', $3, CURRENT_TIMESTAMP)`,
        [loan.user_id, loan.amount, `Loan #${loan.id} Approved`]
      );
    }

    return res.json({ status: true, message: 'Loan request updated', data: loan });
  } catch (err) {
    console.error('Error updating loan request:', err);
    return res.status(500).json({ status: false, message: 'Failed to update loan request' });
  }
});

app.delete('/loan-requests/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await client.query(
      'DELETE FROM loan_requests WHERE id = $1 RETURNING *',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(200).json({ status: false, message: 'Loan request not found' });
    }

    return res.json({ status: true, message: 'Loan request deleted', data: result.rows[0] });
  } catch (err) {
    console.error('Error deleting loan request:', err);
    return res.status(500).json({ status: false, message: 'Failed to delete loan request' });
  }
});

app.get('/team/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 查该用户的上线
    const uplineRes = await client.query(
      `SELECT u2.username AS upline_username
       FROM users u1
       LEFT JOIN users u2 ON u1.referred_by = u2.id
       WHERE u1.id = $1`,
      [id]
    );
    const upline_username = uplineRes.rows[0]?.upline_username || '无上线';

    // 查该用户的下线
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

    res.json({ status: true, upline_username, data });

  } catch (err) {
    console.error('Error fetching team:', err);
    res.status(500).json({ status: false, message: 'Failed to fetch team' });
  }
});

app.get('/checkins/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { rows } = await client.query(`
      SELECT created_at::date AS checkin_date
      FROM checkin
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [id]);

    res.json({ status: true, data: rows });
  } catch (err) {
    console.error('Error fetching checkins:', err);
    res.status(500).json({ status: false, message: 'Failed to fetch checkins' });
  }
});

app.post('/update-lucky-draw', verifyAdminToken, async (req, res) => {
  const { userId, lucky_draw_setting } = req.body;

  if (!userId || !lucky_draw_setting)
    return res.json({ status: false, message: 'Missing required fields' });

  try {
    await client.query(
      `UPDATE users SET lucky_draw_setting = $1 WHERE id = $2`,
      [lucky_draw_setting, userId]
    );

    res.json({ status: true, message: 'Lucky draw setting updated successfully' });
  } catch (err) {
    console.error('Update Lucky Draw Error:', err);
    res.json({ status: false, message: 'Database update failed' });
  }
});

app.get('/draw_record', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await client.query(`
      SELECT u.username, d.prize_name, d.created_at
      FROM draw_records d
      JOIN users u ON u.id = d.user_id
      ORDER BY d.created_at DESC
    `);

    res.json({ status: true, data: rows });
  } catch (err) {
    console.error('Error fetching draw records:', err);
    res.status(500).json({ status: false, message: 'Failed to fetch draw records' });
  }
});

app.get('/config', verifyAdminToken, async (req, res) => {
  try {
    const { rows } = await client.query('SELECT * FROM config ORDER BY key ASC');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching config:', err);
    res.status(500).json({ status:false, message: 'Failed to fetch config' });
  }
});

app.post('/config/:key', verifyAdminToken, async (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;

    const result = await client.query(
      `UPDATE config SET value = $1 WHERE key = $2 RETURNING *`,
      [value, key]
    );

    if (!result.rowCount) {
      return res.status(404).json({ status: false, message: '配置不存在' });
    }

    res.json({ status: true, message: '保存成功', data: result.rows[0] });
  } catch (err) {
    console.error('Error saving config:', err);
    res.status(500).json({ status: false, message: '保存失败' });
  }
});

app.get('/wallet/search', verifyAdminToken, async (req, res) => {
  const { wallet, username } = req.query;

  if (!wallet && !username) 
    return res.json({ status: false, message: 'Missing search query' });

  let where = '';
  let value = '';
  if (wallet) {
    where = 'phone ILIKE $1';
    value = `%${wallet}%`;
  } else if (username) {
    where = 'username ILIKE $1';
    value = `%${username}%`;
  }

  try {
    const { rows } = await client.query(
      `SELECT id, username, phone, email
       FROM users
       WHERE ${where} AND deleted_at IS NULL`,
      [value]
    );

    if (!rows.length) return res.json({ status: false, data: [] });

    res.json({ status: true, data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
