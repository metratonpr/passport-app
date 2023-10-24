<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    function login(Request $request)
    {
        //pegar o usuario e senha
        $credentials = $request->validate([
            'email' => 'string|required|email',
            'password' => 'string|required'
        ]);
        //verificar se ele existe no banco de dados
        //Auth::attempt($credentials)
        if (auth()->attempt($credentials)) {
            $user = Auth::user();
            $user['token'] = $user->createToken('Passaport App')->accessToken;
            return response()->json([
                'user' => $user
            ], 200);
        }
        // em caso de erro
        return response()->json([
            'message' => 'Credenciais estão invalidas'
        ], 402);
    }

    function logout()
    {
        Auth::user()->tokens()->delete();
        return response()->json([
            'message' => 'Logout realizado com sucesso!',
        ]);
    }


}
