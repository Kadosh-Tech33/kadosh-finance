// Config compartilhada do Supabase (Kadosh Finance).
// A anon key é pública por design (protegida pelo RLS, não é segredo —
// ver SECURITY_AUDIT.md). Trocar de projeto ou rotacionar a key: editar
// só aqui, em vez dos 3 arquivos HTML.
const SUPABASE_URL      = 'https://jfzcmofigewimasmhvfs.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_QmECvthsZi6MKr1HG6-vig_F3XqE3sk';

// hCaptcha nos formulários de login/cadastro (index.html e admin.html).
// A sitekey é pública por design. A SECRET key do hCaptcha NÃO vai aqui
// nem em lugar nenhum do repositório: ela fica só no painel do Supabase
// (Authentication → Attack Protection), que valida o token no servidor.
const HCAPTCHA_SITEKEY  = '19765466-b662-4770-bed0-2dca43b66f96';
