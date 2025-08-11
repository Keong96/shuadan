let translations = {}
let currentLang = 'en'

function loadLanguage(lang) {
  return axios.get(`/lang/${lang}.json`)
    .then(res => {
      translations = res.data
      currentLang = lang
      localStorage.setItem('lang', lang)
      applyTranslations()
      updateLanguageTrigger(lang)
    })
    .catch(err => {
      console.error(`Failed to load ${lang}.json`, err)
    })
}

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n')
    if (translations[key]) {
      el.innerText = translations[key]
    }
  })

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (translations[key]) el.placeholder = translations[key];
  });

  document.querySelectorAll('option[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n')
    if (translations[key]) {
      el.innerText = translations[key]
    }
  })
}

function updateLanguageTrigger(lang) {
  const trigger = document.querySelector('.custom-select-trigger')
  const selectedLi = document.querySelector(`.custom-select-options li[data-value="${lang}"]`)
  if (trigger && selectedLi) {
    trigger.innerHTML = selectedLi.innerHTML + ' <i class="bi bi-chevron-down float-end"></i>'
  }
}

function t(key) {
  if (!translations || !currentLang) return key

  const value = translations[key]
  return value || key
}

document.addEventListener('DOMContentLoaded', () => {
  const savedLang = localStorage.getItem('lang') || 'en';
  loadLanguage(savedLang);

  const trigger = document.querySelector('#languageSelectTrigger');
  const options = document.querySelector('#languageSelectOptions');

  if (!trigger || !options) return;

  trigger.addEventListener('click', () => {
    options.style.display = options.style.display === 'block' ? 'none' : 'block';
  });

  // ✅ 只监听语言选择框的选项
  document.querySelectorAll('#languageSelectOptions li').forEach(li => {
    li.addEventListener('click', () => {
      const selectedLang = li.getAttribute('data-value');
      if (selectedLang && selectedLang !== currentLang) {
        loadLanguage(selectedLang);
      }
      options.style.display = 'none';
    });
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#languageSelectWrapper')) {
      options.style.display = 'none';
    }
  });

  document.querySelectorAll('.language-option').forEach(item => {
    item.addEventListener('click', () => {
      const lang = item.getAttribute('data-lang');
      localStorage.setItem('lang', lang);
      loadLanguage(lang);
      bootstrap.Modal.getInstance(document.getElementById('languageModal')).hide();
    });
  });
});
