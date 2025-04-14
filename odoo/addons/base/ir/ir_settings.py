from typing import Self
from odoo import api, fields, models, tools, _
from odoo.exceptions import AccessError, MissingError


class IrSettings(models.Model):
    _name = 'ir.settings'
    _description = "Contains system settings"

    _sql_constraints = [
        ('model_unique', 'unique(model)', 'Only one record for each model can exist.')
    ]

    model = fields.Char(
        name="Setting model",
        required=True,
        index=True
    )

    values = fields.Json(name="Values")

    @api.model
    def create(self, vals):
        self.clear_caches()
        return super(IrSettings, self).create(vals)

    @api.multi
    def write(self, vals):
        self.clear_caches()
        return super(IrSettings, self).write(vals)

    @api.multi
    def unlink(self):
        self.clear_caches()
        return super(IrSettings, self).unlink()

    @api.model
    def get_defaults(self, model: str, condition=False) -> list:
        return list(self.get_model_settings(model).items())

    @api.model
    def get_default(self, model: str, field: str):
        values = self.get_model_settings(model)
        return values.get(field, None)

    @api.model
    def get_model_settings(self, model: str) -> dict:
        record = self.search([('model', '=', model)], limit=1)
        if not record:
            {}
        return record.values

    @api.model
    def set_default(self, model: str, field: str, value) -> Self:
        record = self.search([('model', '=', model)], limit=1)
        if not record:
            record = self.create({'model': model, 'values': {field: value}})
        current_values = record.values
        current_values[field] = value
        record.values = current_values
        return record

    @api.model
    @tools.ormcache('self._uid', 'model')
    def get_defaults_dict(self, model: str, condition=False) -> dict:
        return dict((f, v) for i, f, v in self.get_defaults(model, condition))
