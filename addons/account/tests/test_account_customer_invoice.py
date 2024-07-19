from odoo.addons.account.tests.account_test_users import AccountTestUsers
import datetime


class TestAccountCustomerInvoice(AccountTestUsers):

    def test_customer_invoice(self):
        # I will create bank detail with using manager access rights
        # because account manager can only create bank details.
        self.res_partner_bank_0 = self.env['res.partner.bank'].sudo(self.account_manager.id).create(dict(
            acc_type='bank',
            company_id=self.main_company.id,
            partner_id=self.main_partner.id,
            acc_number='123456789',
            bank_id=self.main_bank.id,
        ))

        # Test with that user which have rights to make Invoicing and payment and who is accountant.
        # Create a customer invoice
        self.account_invoice_obj = self.env['account.invoice']
        self.payment_term = self.env.ref('account.account_payment_term_advance')
        self.journalrec = self.env['account.journal'].search([('type', '=', 'sale')])[0]
        self.partner3 = self.env.ref('base.res_partner_3')
        account_user_type = self.env.ref('account.data_account_type_receivable')
        self.ova = self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_current_assets').id)], limit=1)

        #only adviser can create an account
        self.account_rec1_id = self.account_model.sudo(self.account_manager.id).create(dict(
            code="cust_acc",
            name="customer account",
            user_type_id=account_user_type.id,
            reconcile=True,
        ))

        invoice_line_data = [
            (0, 0,
                {
                    'product_id': self.env.ref('product.product_product_5').id,
                    'quantity': 10.0,
                    'account_id': self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_revenue').id)], limit=1).id,
                    'name': 'product test 5',
                    'price_unit': 100.00,
                }
             )
        ]

        self.account_invoice_customer0 = self.account_invoice_obj.sudo(self.account_user.id).create(dict(
            name="Test Customer Invoice",
            reference_type="none",
            payment_term_id=self.payment_term.id,
            journal_id=self.journalrec.id,
            partner_id=self.partner3.id,
            account_id=self.account_rec1_id.id,
            invoice_line_ids=invoice_line_data
        ))

        # I manually assign tax on invoice
        invoice_tax_line = {
            'name': 'Test Tax for Customer Invoice',
            'manual': 1,
            'amount': 9050,
            'account_id': self.ova.id,
            'invoice_id': self.account_invoice_customer0.id,
        }
        tax = self.env['account.invoice.tax'].create(invoice_tax_line)
        assert tax, "Tax has not been assigned correctly"

        total_before_confirm = self.partner3.total_invoiced

        # I check that Initially customer invoice is in the "Draft" state
        self.assertEqual(self.account_invoice_customer0.state, 'draft')

        # I change the state of invoice to "Proforma2" by clicking PRO-FORMA button
        self.account_invoice_customer0.action_invoice_proforma2()

        # I check that the invoice state is now "Proforma2"
        self.assertEqual(self.account_invoice_customer0.state, 'proforma2')

        # I check that there is no move attached to the invoice
        self.assertEqual(len(self.account_invoice_customer0.move_id), 0)

        # I validate invoice by creating on
        self.account_invoice_customer0.action_invoice_open()

        # I check that the invoice state is "Open"
        self.assertEqual(self.account_invoice_customer0.state, 'open')

        # I check that now there is a move attached to the invoice
        assert self.account_invoice_customer0.move_id, "Move not created for open invoice"

        # I totally pay the Invoice
        self.account_invoice_customer0.pay_and_reconcile(self.env['account.journal'].search([('type', '=', 'bank')], limit=1), 10050.0)

        # I verify that invoice is now in Paid state
        assert (self.account_invoice_customer0.state == 'paid'), "Invoice is not in Paid state"

        total_after_confirm = self.partner3.total_invoiced
        self.assertEqual(total_after_confirm - total_before_confirm, self.account_invoice_customer0.amount_untaxed_signed)

        # I refund the invoice Using Refund Button
        invoice_refund_obj = self.env['account.invoice.refund']
        self.account_invoice_refund_0 = invoice_refund_obj.create(dict(
            description='Refund To China Export',
            date=datetime.date.today(),
            filter_refund='refund'
        ))

        # I clicked on refund button.
        self.account_invoice_refund_0.invoice_refund()

    def test_customer_invoice_tax(self):

        self.env.user.company_id.tax_calculation_rounding_method = 'round_globally'

        payment_term = self.env.ref('account.account_payment_term_advance')
        journalrec = self.env['account.journal'].search([('type', '=', 'sale')])[0]
        partner3 = self.env.ref('base.res_partner_3')
        account_id = self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_revenue').id)], limit=1).id

        tax = self.env['account.tax'].create({
            'name': 'Tax 15.0',
            'amount': 15.0,
            'amount_type': 'percent',
            'type_tax_use': 'sale',
        })

        invoice_line_data = [
            (0, 0,
                {
                    'product_id': self.env.ref('product.product_product_1').id,
                    'quantity': 40.0,
                    'account_id': account_id,
                    'name': 'product test 1',
                    'discount' : 10.00,
                    'price_unit': 2.27,
                    'invoice_line_tax_ids': [(6, 0, [tax.id])],
                }
             ),
              (0, 0,
                {
                    'product_id': self.env.ref('product.product_product_2').id,
                    'quantity': 21.0,
                    'account_id': self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_revenue').id)], limit=1).id,
                    'name': 'product test 2',
                    'discount' : 10.00,
                    'price_unit': 2.77,
                    'invoice_line_tax_ids': [(6, 0, [tax.id])],
                }
             ),
             (0, 0,
                {
                    'product_id': self.env.ref('product.product_product_3').id,
                    'quantity': 21.0,
                    'account_id': self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_revenue').id)], limit=1).id,
                    'name': 'product test 3',
                    'discount' : 10.00,
                    'price_unit': 2.77,
                    'invoice_line_tax_ids': [(6, 0, [tax.id])],
                }
             )
        ]

        invoice = self.env['account.invoice'].create(dict(
            name="Test Customer Invoice",
            reference_type="none",
            payment_term_id=payment_term.id,
            journal_id=journalrec.id,
            partner_id=partner3.id,
            invoice_line_ids=invoice_line_data
        ))

        self.assertEqual(invoice.amount_untaxed, sum([x.base for x in invoice.tax_line_ids]))

    def test_customer_invoice_tax_refund(self):
        company = self.env.user.company_id
        tax_account = self.env['account.account'].create({
            'name': 'TAX',
            'code': 'TAX',
            'user_type_id': self.env.ref('account.data_account_type_current_assets').id,
            'company_id': company.id,
        })

        tax_refund_account = self.env['account.account'].create({
            'name': 'TAX_REFUND',
            'code': 'TAX_R',
            'user_type_id': self.env.ref('account.data_account_type_current_assets').id,
            'company_id': company.id,
        })

        journalrec = self.env['account.journal'].search([('type', '=', 'sale')])[0]
        partner3 = self.env.ref('base.res_partner_3')
        account_id = self.env['account.account'].search([('user_type_id', '=', self.env.ref('account.data_account_type_revenue').id)], limit=1).id

        tax = self.env['account.tax'].create({
            'name': 'Tax 15.0',
            'amount': 15.0,
            'amount_type': 'percent',
            'type_tax_use': 'sale',
            'account_id': tax_account.id,
            'refund_account_id': tax_refund_account.id
        })

        invoice_line_data = [
            (0, 0,
                {
                    'product_id': self.env.ref('product.product_product_1').id,
                    'quantity': 40.0,
                    'account_id': account_id,
                    'name': 'product test 1',
                    'discount': 10.00,
                    'price_unit': 2.27,
                    'invoice_line_tax_ids': [(6, 0, [tax.id])],
                }
             )]

        invoice = self.env['account.invoice'].create(dict(
            name="Test Customer Invoice",
            reference_type="none",
            journal_id=journalrec.id,
            partner_id=partner3.id,
            invoice_line_ids=invoice_line_data
        ))

        invoice.action_invoice_open()

        refund = invoice.refund()
        self.assertEqual(invoice.tax_line_ids.mapped('account_id'), tax_account)
        self.assertEqual(refund.tax_line_ids.mapped('account_id'), tax_refund_account)
