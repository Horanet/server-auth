//  Copyright 2018 Modoolar <info@modoolar.com>
//  License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).
odoo.define("password_security.policy", function(require) {
    "use strict";

    const core = require("web.core");
    const _t = core._t;
    const auth_password_policy = require("auth_password_policy");
    const Policy = auth_password_policy.Policy;

    Policy.include({
        /**
         *
         * @param {Object} info
         * @param {Number} [info.password_length=4]
         * @param {Number} [info.password_lower=1]
         * @param {Number} [info.password_upper=1]
         * @param {Number} [info.password_numeric=1]
         * @param {Number} [info.password_special=1]
         * @param {Number} [info.password_estimate=3]
         */
        init: function(info) {
            this._super(info);

            this._password_length = info.password_length || 4;
            this._password_lower = info.password_lower || 1;
            this._password_upper = info.password_upper || 1;
            this._password_numeric = info.password_numeric || 1;
            this._password_special = info.password_special || 1;
            this._password_estimate = info.password_estimate || 3;
        },

        toString: function() {
            const msgs = [];

            if (this._password_length > 1) {
                msgs.push(
                    _.str.sprintf(_t("at least %d characters"), this._password_length)
                );
            } else {
                msgs.push(
                    _.str.sprintf(_t("at least %d character"), this._password_length)
                );
            }

            if (this._password_lower > 1) {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d lower case characters"),
                        this._password_lower
                    )
                );
            } else {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d lower case character"),
                        this._password_lower
                    )
                );
            }

            if (this._password_upper > 1) {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d upper case characters"),
                        this._password_upper
                    )
                );
            } else {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d upper case character"),
                        this._password_upper
                    )
                );
            }

            if (this._password_numeric > 1) {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d numeric characters"),
                        this._password_numeric
                    )
                );
            } else {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d numeric character"),
                        this._password_numeric
                    )
                );
            }

            if (this._password_special > 1) {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d special characters"),
                        this._password_special
                    )
                );
            } else {
                msgs.push(
                    _.str.sprintf(
                        _t("at least %d special character"),
                        this._password_special
                    )
                );
            }

            return msgs.join(", ");
        },

        _calculate_password_score: function(pattern, min_count, password) {
            const matchMinCount = new RegExp(
                "(.*" + pattern + ".*){" + min_count + ",}",
                "g"
            ).exec(password);
            if (matchMinCount === null) {
                return 0;
            }

            let count = 0;
            const regExp = new RegExp(pattern, "g");

            while (regExp.exec(password) !== null) {
                count++;
            }

            return Math.min(count / min_count, 1.0);
        },

        _estimate: function(password) {
            const zxcvbn = window.zxcvbn;
            return Math.min(zxcvbn(password).score / 4.0, 1.0);
        },

        score: function(password) {
            const lengthscore = Math.min(password.length / this._password_length, 1.0);
            const loverscore = this._calculate_password_score(
                "[a-z]",
                this._password_lower,
                password
            );
            const upperscore = this._calculate_password_score(
                "[A-Z]",
                this._password_upper,
                password
            );
            const numericscore = this._calculate_password_score(
                "\\d",
                this._password_numeric,
                password
            );
            const specialscore = this._calculate_password_score(
                "[\\W_]",
                this._password_special,
                password
            );
            const estimatescore = this._estimate(password);

            return (
                lengthscore *
                loverscore *
                upperscore *
                numericscore *
                specialscore *
                estimatescore
            );
        },
    });

    const recommendations = {
        score: auth_password_policy.recommendations.score,
        policies: [
            new Policy({
                password_length: 12,
                password_upper: 3,
                password_lower: 3,
                password_numeric: 3,
                password_special: 3,
                password_estimate: 3,
            }),
            new Policy({
                password_length: 16,
                password_upper: 4,
                password_lower: 4,
                password_numeric: 4,
                password_special: 4,
                password_estimate: 4,
            }),
        ],
    };

    auth_password_policy.recommendations = recommendations;
});

odoo.define("password_security.Meter", function(require) {
    "use strict";

    const session = require("web.session");
    const PasswordMeter = require("auth_password_policy.Meter");

    PasswordMeter.include({
        init: function(parent, required, recommended) {
            this._super(parent);
            this._required = required;
            this._recommended = recommended;
        },
        willStart: function() {
            return Promise.all([this._super.apply(this, arguments), session.is_bound]);
        },
    });
    return PasswordMeter;
});
