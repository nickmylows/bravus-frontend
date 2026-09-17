require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

//const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Obrigatório para o Neon aceitar a conexão externa
    }
});

module.exports = pool; // (Ou a forma como você já exportava antes)

// Chave secreta para assinar os crachás virtuais (puxando direto do cofre .env sem aspas)
const SEGREDO_JWT = process.env.JWT_SECRET;

// 1. ROTA DE CADASTRO (Agora com criptografia)
app.post('/api/usuarios', async (req, res) => {
    try {
        const { email, senha, perfil } = req.body;
        
        // Embaralha a senha 10 vezes antes de salvar
        const senhaCriptografada = await bcrypt.hash(senha, 10);
        
        const novoUsuario = await pool.query(
            "INSERT INTO usuarios (email, senha_hash, perfil) VALUES ($1, $2, $3) RETURNING id, email, perfil",
            [email, senhaCriptografada, perfil]
        );
        
        res.status(201).json({ mensagem: "Usuário cadastrado com segurança!", usuario: novoUsuario.rows[0] });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao criar usuário." });
    }
});

// 2. ROTA DE LOGIN (Gera o Token JWT)
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;

        // Verifica se o email existe no banco
        const resultado = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);
        if (resultado.rows.length === 0) {
            return res.status(401).json({ erro: "Usuário não encontrado." });
        }

        const usuario = resultado.rows[0];

        // Compara a senha digitada com a senha embaralhada no banco
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
        if (!senhaValida) {
            return res.status(401).json({ erro: "Senha incorreta." });
        }

        // Cria o "crachá" usando a constante que abriu o cofre
        const token = jwt.sign(
            { id: usuario.id, perfil: usuario.perfil }, 
            SEGREDO_JWT, 
            { expiresIn: '8h' }
        );

        res.json({ 
            mensagem: "Login realizado com sucesso!", 
            token: token,
            perfil: usuario.perfil 
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao fazer login." });
    }
});
// O "Segurança da Porta" (Middleware)
const verificarAcesso = (req, res, next) => {
    // Busca o crachá no cabeçalho da requisição
    const tokenCompleto = req.headers['authorization'];
    
    if (!tokenCompleto) {
        return res.status(403).json({ erro: "Acesso negado: Nenhum crachá fornecido." });
    }

    // O padrão da web envia o token como "Bearer hdsahd8723...". Precisamos cortar a palavra Bearer.
    const tokenReal = tokenCompleto.split(' ')[1];

    // Audita a assinatura do token
    jwt.verify(tokenReal, SEGREDO_JWT, (erro, dadosDescriptografados) => {
        if (erro) {
            return res.status(401).json({ erro: "Crachá inválido ou vencido." });
        }
        
        // Se for válido, guarda os dados (id e perfil) e deixa passar para a rota
        req.usuario = dadosDescriptografados;
        next(); 
    });
};

// Rota restrita para Clientes
app.get('/api/painel-cliente', verificarAcesso, (req, res) => {
    if (req.usuario.perfil !== 'CLIENTE') {
        return res.status(403).json({ erro: "Área restrita: Apenas clientes." });
    }
    res.json({ mensagem: "Bem-vindo ao seu painel, cliente!" });
});

// Rota restrita para Profissionais
app.get('/api/painel-profissional', verificarAcesso, (req, res) => {
    if (req.usuario.perfil !== 'PROFISSIONAL') {
        return res.status(403).json({ erro: "Área restrita: Apenas barbeiros." });
    }
    res.json({ mensagem: "Bem-vindo à gestão da sua agenda!" });
});
// 1. Rota para cadastrar um Serviço
app.post('/api/servicos', async (req, res) => {
    try {
        const { nome, descricao, preco, duracao_minutos } = req.body;
        const novoServico = await pool.query(
            "INSERT INTO servicos (nome, descricao, preco, duracao_minutos) VALUES ($1, $2, $3, $4) RETURNING *",
            [nome, descricao, preco, duracao_minutos]
        );
        res.status(201).json(novoServico.rows[0]);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cadastrar serviço." });
    }
});

// 2. Rota para completar o perfil do Cliente
app.post('/api/clientes', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'CLIENTE') return res.status(403).json({ erro: "Apenas clientes." });
        
        const { nome, telefone } = req.body;
        const id_usuario = req.usuario.id; // O Node.js pega isso automaticamente do Token!
        
        const novoCliente = await pool.query(
            "INSERT INTO clientes (id_usuario, nome, telefone) VALUES ($1, $2, $3) RETURNING *",
            [id_usuario, nome, telefone]
        );
        res.status(201).json(novoCliente.rows[0]);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao criar perfil de cliente." });
    }
});

// Rota para buscar os dados do cliente logado
app.get('/api/meu-perfil', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'CLIENTE') {
            return res.status(403).json({ erro: "Acesso negado." });
        }

        // O JOIN une a tabela clientes e usuarios para buscar o nome e o email ao mesmo tempo
        const resultado = await pool.query(
            `SELECT c.nome, c.telefone, u.email 
             FROM clientes c 
             JOIN usuarios u ON c.id_usuario = u.id 
             WHERE c.id_usuario = $1`, 
            [req.usuario.id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Perfil não encontrado." });
        }

        res.json(resultado.rows[0]);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao buscar dados do perfil." });
    }
});

// 3. Rota para completar o perfil do Profissional
app.post('/api/profissionais', verificarAcesso, async (req, res) => {
    try {
        // Nova regra: Permite ADMIN ou o próprio PROFISSIONAL logado
        if (req.usuario.perfil !== 'ADMIN' && req.usuario.perfil !== 'PROFISSIONAL') {
            return res.status(403).json({ erro: "Acesso negado." });
        }
        
        const { nome, especialidade } = req.body;
        // Pega o ID diretamente do Token da pessoa logada
        const id_usuario = req.usuario.id; 
        
        const novoProfissional = await pool.query(
            "INSERT INTO profissionais (id_usuario, nome, especialidade) VALUES ($1, $2, $3) RETURNING *",
            [id_usuario, nome, especialidade]
        );
        res.status(201).json(novoProfissional.rows[0]);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao criar perfil de profissional." });
    }
});

app.get('/api/profissionais', async (req, res) => {
    try {
        const resultado = await pool.query("SELECT id, nome, especialidade FROM profissionais ORDER BY nome ASC");
        res.json(resultado.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao carregar a lista de profissionais." });
    }
});

// Rota para o Cliente fazer um Agendamento (Com trava de conflito)
app.post('/api/agendamentos', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'CLIENTE') {
            return res.status(403).json({ erro: "Apenas clientes podem fazer agendamentos." });
        }

        const { id_profissional, id_servico, data_hora } = req.body;
        
        const clienteResult = await pool.query(
            "SELECT id FROM clientes WHERE id_usuario = $1", 
            [req.usuario.id]
        );

        if (clienteResult.rows.length === 0) {
            return res.status(400).json({ erro: "Perfil de cliente não encontrado." });
        }

        const id_cliente = clienteResult.rows[0].id;

        // NOVA REGRA: Verifica se o profissional já tem agendamento ativo neste horário
        const checagemHorario = await pool.query(
            "SELECT id FROM agendamentos WHERE id_profissional = $1 AND data_hora = $2 AND status != 'CANCELADO'",
            [id_profissional, data_hora]
        );

        if (checagemHorario.rows.length > 0) {
            return res.status(409).json({ erro: "Este horário já está reservado com o profissional selecionado." });
        }

        const novoAgendamento = await pool.query(
            "INSERT INTO agendamentos (id_cliente, id_profissional, id_servico, data_hora) VALUES ($1, $2, $3, $4) RETURNING *",
            [id_cliente, id_profissional, id_servico, data_hora]
        );

        res.status(201).json({
            mensagem: "Horário reservado com sucesso!",
            agendamento: novoAgendamento.rows[0]
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao realizar agendamento." });
    }
});

// Rota para listar todos os serviços (O Catálogo)
app.get('/api/servicos', async (req, res) => {
    try {
        // Busca todos os registros na tabela de serviços
        const resultado = await pool.query("SELECT id, nome, descricao, preco, duracao_minutos FROM servicos ORDER BY nome ASC");
        res.json(resultado.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao carregar o catálogo de serviços." });
    }
});

//app.post('/api/profissionais', verificarAcesso, async (req, res) => {
   // try {
        // Permite que o perfil PROFISSIONAL crie seus próprios dados
      //  if (req.usuario.perfil !== 'ADMIN' && req.usuario.perfil !== 'PROFISSIONAL') {
      //      return res.status(403).json({ erro: "Acesso negado." });
      //  }
        
    //    const { nome, especialidade } = req.body;
      //  const id_usuario = req.usuario.id; 
        
     //   const novoProfissional = await pool.query(
    //        "INSERT INTO profissionais (id_usuario, nome, especialidade) VALUES ($1, $2, $3) RETURNING *",
     //       [id_usuario, nome, especialidade]
     //   );
     //   res.status(201).json(novoProfissional.rows[0]);
  //  } catch (erro) {
     //   console.error(erro);
     //   res.status(500).json({ erro: "Erro ao criar perfil de profissional." });
  //  }
//});

// Rota para o Barbeiro consultar sua agenda e receitas
app.get('/api/agenda-profissional', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'PROFISSIONAL') {
            return res.status(403).json({ erro: "Acesso negado. Relatório exclusivo para profissionais." });
        }

        // Descobre o ID do profissional associado ao usuário logado
        const profResult = await pool.query(
            "SELECT id FROM profissionais WHERE id_usuario = $1", 
            [req.usuario.id]
        );

        if (profResult.rows.length === 0) {
            return res.status(400).json({ erro: "Perfil de profissional não localizado." });
        }

        const id_profissional = profResult.rows[0].id;

        // O JOIN cruza as 3 tabelas (Agendamentos + Clientes + Serviços)
        const queryRelatorio = `
            SELECT 
                a. id,
                a.data_hora,
                a.status,
                c.nome AS nome_cliente,
                s.nome AS servico_realizado,
                s.preco AS valor_receita
            FROM agendamentos a
            JOIN clientes c ON a.id_cliente = c.id
            JOIN servicos s ON a.id_servico = s.id
            WHERE a.id_profissional = $1
            ORDER BY a.data_hora ASC
        `;

        const agenda = await pool.query(queryRelatorio, [id_profissional]);
        
        res.json({
            total_atendimentos: agenda.rows.length,
            relatorio: agenda.rows
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao extrair o relatório da agenda." });
    }
});

// Rota para atualizar o status do agendamento (Reconhecimento da receita)
app.patch('/api/agendamentos/:id/status', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'PROFISSIONAL') {
            return res.status(403).json({ erro: "Acesso negado. Apenas o profissional pode dar baixa." });
        }

        const idAgendamento = req.params.id;
        const { status } = req.body;

        // Atualiza o status no banco de dados
        const resultado = await pool.query(
            "UPDATE agendamentos SET status = $1 WHERE id = $2 RETURNING id, status",
            [status, idAgendamento]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Agendamento não encontrado." });
        }

        res.json({ 
            mensagem: "Serviço baixado com sucesso!", 
            agendamento: resultado.rows[0] 
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao atualizar o status." });
    }
});

// Rota para LER os dados do perfil (Garante que puxamos o telefone também)
app.get('/api/meu-perfil', verificarAcesso, async (req, res) => {
    try {
        const query = `
            SELECT u.email, c.nome, c.telefone 
            FROM usuarios u
            JOIN clientes c ON u.id = c.id_usuario
            WHERE u.id = $1
        `;
        const resultado = await pool.query(query, [req.usuario.id]);
        
        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Perfil não encontrado." });
        }
        res.json(resultado.rows[0]);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao buscar perfil." });
    }
});

// Nova Rota para ATUALIZAR os dados do perfil
app.put('/api/meu-perfil', verificarAcesso, async (req, res) => {
    const { nome, email, telefone } = req.body;

    try {
        // 1. Verifica se o novo e-mail já está sendo usado por OUTRA pessoa
        const emailCheck = await pool.query(
            "SELECT id FROM usuarios WHERE email = $1 AND id != $2", 
            [email, req.usuario.id]
        );
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ erro: "Este e-mail já está em uso por outra conta." });
        }

        // 2. Atualiza o e-mail na tabela de login
        await pool.query("UPDATE usuarios SET email = $1 WHERE id = $2", [email, req.usuario.id]);
        
        // 3. Atualiza o nome e telefone na tabela de clientes
        await pool.query("UPDATE clientes SET nome = $1, telefone = $2 WHERE id_usuario = $3", [nome, telefone, req.usuario.id]);

        res.json({ mensagem: "Perfil atualizado com sucesso!" });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao atualizar os dados." });
    }
});

// Rota para o Cliente consultar seu histórico de agendamentos
app.get('/api/meus-agendamentos', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'CLIENTE') {
            return res.status(403).json({ erro: "Acesso negado. Área exclusiva para clientes." });
        }

        // Descobre o ID do cliente associado ao usuário logado
        const clienteResult = await pool.query(
            "SELECT id FROM clientes WHERE id_usuario = $1", 
            [req.usuario.id]
        );

        if (clienteResult.rows.length === 0) {
            return res.status(400).json({ erro: "Perfil de cliente não localizado." });
        }

        const id_cliente = clienteResult.rows[0].id;

        // O JOIN agora cruza Agendamentos + Profissionais + Serviços filtrando pelo Cliente
        const queryHistorico = `
            SELECT 
                a.id, 
                a.data_hora,
                a.status,
                p.nome AS nome_profissional,
                s.nome AS servico_realizado,
                s.preco AS valor_servico
            FROM agendamentos a
            JOIN profissionais p ON a.id_profissional = p.id
            JOIN servicos s ON a.id_servico = s.id
            WHERE a.id_cliente = $1
            ORDER BY a.data_hora DESC
        `;

        const historico = await pool.query(queryHistorico, [id_cliente]);
        
        res.json(historico.rows);

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao extrair o histórico de agendamentos." });
    }
});

// Rota para o Cliente cancelar o PRÓPRIO agendamento
app.patch('/api/meus-agendamentos/:id/cancelar', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'CLIENTE') {
            return res.status(403).json({ erro: "Acesso negado. Apenas clientes podem cancelar por aqui." });
        }

        const idAgendamento = req.params.id;

        // 1. Pega o ID real do cliente no banco
        const clienteResult = await pool.query(
            "SELECT id FROM clientes WHERE id_usuario = $1", 
            [req.usuario.id]
        );

        if (clienteResult.rows.length === 0) {
            return res.status(400).json({ erro: "Perfil de cliente não localizado." });
        }

        const id_cliente = clienteResult.rows[0].id;

        // 2. Atualiza para CANCELADO. 
        // A regra "id_cliente = $2" garante que ele não cancele o horário de outra pessoa.
        // A regra "status = 'PENDENTE'" impede o cancelamento de serviços já pagos/concluídos.
        const resultado = await pool.query(
            "UPDATE agendamentos SET status = 'CANCELADO' WHERE id = $1 AND id_cliente = $2 AND status = 'PENDENTE' RETURNING id, status",
            [idAgendamento, id_cliente]
        );

        if (resultado.rows.length === 0) {
            return res.status(400).json({ erro: "Agendamento não encontrado ou já processado (concluído/cancelado)." });
        }

        res.json({ 
            mensagem: "Agendamento cancelado com sucesso!", 
            agendamento: resultado.rows[0] 
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cancelar o agendamento." });
    }
});

// Rota exclusiva para o ADMIN cadastrar novos serviços
app.post('/api/servicos', verificarAcesso, async (req, res) => {
    try {
        if (req.usuario.perfil !== 'ADMIN') {
            return res.status(403).json({ erro: "Acesso negado. Exclusivo para gestão." });
        }

        const { nome, duracao_minutos, preco } = req.body;

        const novoServico = await pool.query(
            "INSERT INTO servicos (nome, duracao_minutos, preco) VALUES ($1, $2, $3) RETURNING *",
            [nome, duracao_minutos, preco]
        );

        res.status(201).json({
            mensagem: "Serviço adicionado ao catálogo!",
            servico: novoServico.rows[0]
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cadastrar o serviço no banco." });
    }
});


// Rota para buscar os horários ocupados de um profissional em uma data específica
app.get('/api/horarios-ocupados', async (req, res) => {
    try {
        const { id_profissional, data } = req.query;
        
        if (!id_profissional || !data) {
            return res.status(400).json({ erro: "Profissional e data são obrigatórios." });
        }

        // Busca no banco os agendamentos ativos (não cancelados) para o profissional na data informada
        const resultado = await pool.query(
            "SELECT data_hora FROM agendamentos WHERE id_profissional = $1 AND DATE(data_hora) = $2 AND status != 'CANCELADO'",
            [id_profissional, data]
        );

        // Extrai apenas a string do horário (Ex: '14:00') do Timestamp do banco
        const horariosBloqueados = resultado.rows.map(linha => {
            const dataObjeto = new Date(linha.data_hora);
            return dataObjeto.toTimeString().substring(0, 5); 
        });

        res.json(horariosBloqueados);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao consultar horários disponíveis." });
    }
});

// Solicitar recuperação de senha
app.post('/api/esqueci-senha', async (req, res) => {
    try {
        const { email } = req.body;
        const resultado = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);
        
        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "E-mail não encontrado." });
        }

        const usuario = resultado.rows[0];
        
        // Cria uma chave única juntando o seu segredo padrão com a senha atual do usuário
        const segredoReset = SEGREDO_JWT + usuario.senha_hash; 
        
        // Gera um token que expira em 15 minutos
        const token = jwt.sign({ email: usuario.email, id: usuario.id }, segredoReset, { expiresIn: '15m' });
        
        // Em produção, isso seria enviado por e-mail. Aqui, enviamos para o front-end exibir.
        res.json({ 
            mensagem: "Token gerado com sucesso.", 
            token_recuperacao: token,
            id_usuario: usuario.id 
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao gerar solicitação." });
    }
});

// Redefinir a senha com o token
app.post('/api/redefinir-senha', async (req, res) => {
    try {
        const { id_usuario, token, novaSenha } = req.body;

        const resultado = await pool.query("SELECT * FROM usuarios WHERE id = $1", [id_usuario]);
        if (resultado.rows.length === 0) return res.status(404).json({ erro: "Usuário não encontrado." });

        const usuario = resultado.rows[0];
        const segredoReset = SEGREDO_JWT + usuario.senha_hash;

        // Valida se o token é real, se não expirou e se a senha não foi trocada no meio tempo
        jwt.verify(token, segredoReset, async (erro, dados) => {
            if (erro) {
                return res.status(401).json({ erro: "Link de recuperação inválido ou expirado." });
            }

            // Criptografa a nova senha e salva no banco
            const senhaCriptografada = await bcrypt.hash(novaSenha, 10);
            await pool.query(
                "UPDATE usuarios SET senha_hash = $1 WHERE id = $2",
                [senhaCriptografada, id_usuario]
            );

            res.json({ mensagem: "Senha atualizada com sucesso!" });
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao redefinir a senha." });
    }
});

app.post('/api/admin/profissionais', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') {
        return res.status(403).json({ erro: "Acesso negado. Apenas administradores." });
    }

    const { nome, especialidade, cpf, telefone, email, senha } = req.body;

    try {
        // 1. Verifica se o e-mail já existe para evitar duplicidade
        const emailExiste = await pool.query("SELECT id FROM usuarios WHERE email = $1", [email]);
        if (emailExiste.rows.length > 0) {
            return res.status(400).json({ erro: "Este e-mail já está em uso." });
        }

        // 2. Criptografa a senha e cria a credencial de login
        const senhaHash = await bcrypt.hash(senha, 10);
        const novoUsuario = await pool.query(
            "INSERT INTO usuarios (email, senha_hash, perfil) VALUES ($1, $2, 'PROFISSIONAL') RETURNING id",
            [email, senhaHash]
        );
        
        const idUsuario = novoUsuario.rows[0].id;

        // 3. Cria o perfil do barbeiro vinculado ao novo login
        await pool.query(
            "INSERT INTO profissionais (id_usuario, nome, especialidade, cpf, telefone) VALUES ($1, $2, $3, $4, $5)",
            [idUsuario, nome, especialidade, cpf, telefone]
        );

        res.status(201).json({ mensagem: "Profissional cadastrado com sucesso!" });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cadastrar profissional." });
    }
});

app.get('/api/admin/relatorios', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') {
        return res.status(403).json({ erro: "Acesso negado." });
    }

    const { id_profissional, data_inicio, data_fim } = req.query;

    if (!id_profissional || !data_inicio || !data_fim) {
        return res.status(400).json({ erro: "Filtros incompletos." });
    }

    try {
        // Busca os agendamentos concluídos no período informado
        const query = `
            SELECT a.data_hora, a.status, s.nome as servico_realizado, s.preco as valor_receita, c.nome as nome_cliente
            FROM agendamentos a
            JOIN servicos s ON a.id_servico = s.id
            JOIN clientes c ON a.id_cliente = c.id
            WHERE a.id_profissional = $1 
              AND a.data_hora >= $2 
              AND a.data_hora <= $3 
              AND a.status = 'CONCLUIDO'
            ORDER BY a.data_hora DESC
        `;
        
        // Formata as datas para cobrir o dia inteiro (00:00 às 23:59)
        const valores = [id_profissional, `${data_inicio} 00:00:00`, `${data_fim} 23:59:59`];
        const resultado = await pool.query(query, valores);

        // Calcula o faturamento total via JavaScript
        const faturamentoTotal = resultado.rows.reduce((acc, item) => acc + parseFloat(item.valor_receita), 0);

        res.json({
            atendimentos: resultado.rows,
            total_faturado: faturamentoTotal,
            quantidade: resultado.rows.length
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao gerar relatório." });
    }
});

// Excluir Serviço
app.delete('/api/admin/servicos/:id', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') return res.status(403).json({ erro: "Acesso negado." });
    
    try {
        await pool.query("DELETE FROM servicos WHERE id = $1", [req.params.id]);
        res.json({ mensagem: "Serviço removido com sucesso." });
    } catch (erro) {
        res.status(400).json({ erro: "Não é possível excluir um serviço que já possui agendamentos." });
    }
});

// Excluir Profissional
app.delete('/api/admin/profissionais/:id', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') return res.status(403).json({ erro: "Acesso negado." });
    
    try {
        // Busca o ID de login vinculado ao profissional antes de deletar
        const resultado = await pool.query("SELECT id_usuario FROM profissionais WHERE id = $1", [req.params.id]);
        
        if (resultado.rows.length > 0) {
            const idUsuario = resultado.rows[0].id_usuario;
            // O banco apaga o perfil automaticamente se a restrição de chave estrangeira permitir
            await pool.query("DELETE FROM profissionais WHERE id = $1", [req.params.id]);
            await pool.query("DELETE FROM usuarios WHERE id = $1", [idUsuario]);
            res.json({ mensagem: "Profissional e credenciais removidos." });
        } else {
            res.status(404).json({ erro: "Profissional não encontrado." });
        }
    } catch (erro) {
        res.status(400).json({ erro: "Não é possível excluir um barbeiro com histórico de agendamentos." });
    }
});

// Atualizar Serviço
app.put('/api/admin/servicos/:id', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') return res.status(403).json({ erro: "Acesso negado." });
    
    const { nome, duracao_minutos, preco } = req.body;
    try {
        await pool.query(
            "UPDATE servicos SET nome = $1, duracao_minutos = $2, preco = $3 WHERE id = $4", 
            [nome, duracao_minutos, preco, req.params.id]
        );
        res.json({ mensagem: "Serviço atualizado com sucesso." });
    } catch (erro) {
        res.status(500).json({ erro: "Erro ao atualizar serviço." });
    }
});

// Atualizar Profissional (Dados de Perfil)
app.put('/api/admin/profissionais/:id', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'ADMIN') return res.status(403).json({ erro: "Acesso negado." });
    
    const { nome, especialidade, cpf, telefone } = req.body;
    try {
        await pool.query(
            "UPDATE profissionais SET nome = $1, especialidade = $2, cpf = $3, telefone = $4 WHERE id = $5", 
            [nome, especialidade, cpf, telefone, req.params.id]
        );
        res.json({ mensagem: "Profissional atualizado com sucesso." });
    } catch (erro) {
        res.status(500).json({ erro: "Erro ao atualizar profissional." });
    }
});

// Rota: Relatório de Faturamento Individual do Barbeiro
app.get('/api/barbeiro/relatorios', verificarAcesso, async (req, res) => {
    if (req.usuario.perfil !== 'PROFISSIONAL') {
        return res.status(403).json({ erro: "Acesso negado." });
    }

    const { data_inicio, data_fim } = req.query;

    if (!data_inicio || !data_fim) {
        return res.status(400).json({ erro: "Filtros de data incompletos." });
    }

    try {
        // Descobre o ID do profissional vinculado a este login
        const profResult = await pool.query("SELECT id FROM profissionais WHERE id_usuario = $1", [req.usuario.id]);
        if (profResult.rows.length === 0) return res.status(404).json({ erro: "Perfil profissional não encontrado." });
        
        const idProfissional = profResult.rows[0].id;

        // Busca o faturamento no período
        const query = `
            SELECT a.data_hora, a.status, s.nome as servico_realizado, s.preco as valor_receita, c.nome as nome_cliente
            FROM agendamentos a
            JOIN servicos s ON a.id_servico = s.id
            JOIN clientes c ON a.id_cliente = c.id
            WHERE a.id_profissional = $1 
              AND a.data_hora >= $2 
              AND a.data_hora <= $3 
              AND a.status = 'CONCLUIDO'
            ORDER BY a.data_hora DESC
        `;
        
        const valores = [idProfissional, `${data_inicio} 00:00:00`, `${data_fim} 23:59:59`];
        const resultado = await pool.query(query, valores);

        const faturamentoTotal = resultado.rows.reduce((acc, item) => acc + parseFloat(item.valor_receita), 0);

        res.json({
            atendimentos: resultado.rows,
            total_faturado: faturamentoTotal,
            quantidade: resultado.rows.length
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao gerar relatório." });
    }
});

const PORTA = process.env.PORT || 3000;
app.listen(PORTA, () => {
    console.log(`Servidor rodando na porta ${PORTA}`);
});