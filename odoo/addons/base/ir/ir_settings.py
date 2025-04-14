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
    def set_default(self, model: str, field: str, value) -> None:
        record = self.search([('model', '=', model)], limit=1)
        if not record:
            record = self.create({'model': model, 'values': {field: value}})
        current_values = record.values
        current_values[field] = value
        record.values = current_values
        return
