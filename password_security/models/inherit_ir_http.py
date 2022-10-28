from odoo import models


class IrHttp(models.AbstractModel):
    """Overload to add module translations in front."""

    # region Private attributes
    _inherit = "ir.http"

    # endregion

    # region Default methods
    # endregion

    # region Fields declaration
    # endregion

    # region Fields method
    # endregion

    # region Constraints and Onchange
    # endregion

    # region CRUD (overrides)
    @classmethod
    def _get_translation_frontend_modules_name(cls):
        """Add the module name to the list of module that have frontend translation.

        override :meth:
        odoo.addons.http_routing.models.ir_http._get_translation_frontend_modules_name
        """
        # noinspection PyProtectedMember
        mods = super(IrHttp, cls)._get_translation_frontend_modules_name()
        return mods + ["auth_password_policy", "password_security"]

    # endregion

    # region Actions
    # endregion

    # region Model methods
    # endregion
