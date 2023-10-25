<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;


class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
{
    $validator = Validator::make($request->all(), [
        'email' => 'required|string|email',
        'password' => 'required|string',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'message' => 'Dados de entrada inválidos',
            'errors' => $validator->errors(),
        ], 422); // Código 422 para Entidade não processável (Unprocessable Entity)
    }

    if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
        $user = Auth::user();
        $token = $user->createToken('Passport App')->accessToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
        ], 200);
    }

    return response()->json([
        'message' => 'Credenciais inválidas'
    ], 401); // Código 401 para Não Autorizado (Unauthorized)
}

public function logout()
{
    try {
        Auth::guard('api')->user()->token()->revoke();
    } catch (\Exception $e) {
        return response()->json([
            'message' => 'Token inválido ou não autorizado.',
        ], 401);
    }

    return response()->json([
        'message' => 'Logout realizado com sucesso!',
    ], 200);
}

    public function register(Request $request)
{
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:6',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'message' => 'Erro de validação',
            'errors' => $validator->errors()
        ], 422); // Código 422 para entidades não processáveis
    }

    $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => Hash::make($request->password),
    ]);

    return response()->json([
        'message' => 'Usuário criado com sucesso',
        'user' => $user
    ], 201); // Código 201 para criação bem-sucedida
}
}
