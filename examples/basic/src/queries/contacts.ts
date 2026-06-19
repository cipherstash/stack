import { contactsTable } from '../encryption/index'
import { eSupabase } from '../lib/supabase/encrypted'

// Example queries using encrypted Supabase wrapper

export async function getAllContacts() {
  const { data, error } = await eSupabase
    .from('contacts', contactsTable)
    .select('id, name, email, role') // explicit columns, no *
    .order('created_at', { ascending: false })

  return { data, error }
}

export async function getContactsByRole(role: string) {
  const { data, error } = await eSupabase
    .from('contacts', contactsTable)
    .select('id, name, email, role')
    .eq('role', role) // auto-encrypted

  return { data, error }
}

export async function searchContactsByName(searchTerm: string) {
  const { data, error } = await eSupabase
    .from('contacts', contactsTable)
    .select('id, name, email, role')
    .ilike('name', `%${searchTerm}%`) // auto-encrypted

  return { data, error }
}

export async function createContact(contact: {
  name: string
  email: string
  role: string
}) {
  const { data, error } = await eSupabase
    .from('contacts', contactsTable)
    .insert(contact) // auto-encrypted
    .select('id, name, email, role')
    .single()

  return { data, error }
}

export async function updateContact(
  id: string,
  updates: Partial<{ name: string; email: string; role: string }>,
) {
  const { data, error } = await eSupabase
    .from('contacts', contactsTable)
    .update(updates) // auto-encrypted
    .eq('id', id)
    .select('id, name, email, role')
    .single()

  return { data, error }
}

export async function deleteContact(id: string) {
  const { error } = await eSupabase
    .from('contacts', contactsTable)
    .delete()
    .eq('id', id)

  return { error }
}
