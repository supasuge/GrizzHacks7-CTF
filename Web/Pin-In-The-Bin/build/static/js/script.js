document.addEventListener('DOMContentLoaded', function() {
   
    const themeSwitchers = document.querySelectorAll('[data-theme-switcher]');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
    
    
    const savedTheme = localStorage.getItem('theme') || 'auto';
    setTheme(savedTheme);
    
    updateActiveTheme(savedTheme);

    function setTheme(theme) {
        if (theme === 'auto') {
            document.documentElement.setAttribute('data-theme', prefersDark.matches ? 'dark' : 'light');
        } else {
            document.documentElement.setAttribute('data-theme', theme);
        }
        localStorage.setItem('theme', theme);
        updateActiveTheme(theme);
    }

    function updateActiveTheme(theme) {
        themeSwitchers.forEach(switcher => {
            switcher.classList.toggle('active', switcher.dataset.themeSwitcher === theme);
        });
    }

    themeSwitchers.forEach(switcher => {
        switcher.addEventListener('click', (e) => {
            e.preventDefault();
            const theme = switcher.dataset.themeSwitcher;
            setTheme(theme);
        });
    });

    prefersDark.addEventListener('change', (e) => {
        if (localStorage.getItem('theme') === 'auto') {
            setTheme('auto');
        }
    });

    const flashMessages = document.querySelectorAll('.notice');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 300);
        }, 5000);
    });

    const pinInputs = document.querySelectorAll('input[pattern="\\d{4}"]');
    pinInputs.forEach(input => {
        input.addEventListener('keyup', function(e) {
            if (this.value.length === 4) {
                this.classList.add('complete');
            } else {
                this.classList.remove('complete');
            }
        });

        input.addEventListener('input', function(e) {
            this.value = this.value.replace(/\D/g, '');
            if (this.value.length > 4) {
                this.value = this.value.slice(0, 4);
            }
        });
    });

    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                field.classList.remove('invalid');
                const existingError = field.nextElementSibling;
                if (existingError?.classList.contains('error-message')) {
                    existingError.remove();
                }

                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('invalid');
                    addErrorMessage(field, `${field.placeholder || 'This field'} is required`);
                }
                
                else if (field.pattern && !new RegExp(field.pattern).test(field.value)) {
                    isValid = false;
                    field.classList.add('invalid');
                    addErrorMessage(field, `Please enter a valid ${field.placeholder.toLowerCase()}`);
                }
            });

            if (!isValid) {
                e.preventDefault();
            }
        });
    });

    function addErrorMessage(field, message) {
        const errorMsg = document.createElement('small');
        errorMsg.classList.add('error-message');
        errorMsg.style.color = 'var(--pico-form-element-invalid-active-border-color)';
        errorMsg.textContent = message;
        field.parentNode.insertBefore(errorMsg, field.nextSibling);
    }
});