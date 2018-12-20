<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ResetsPasswords;
use Illuminate\Http\Request;
use App\User;
use Mail;
use App\Mail\ResetPasswordMail;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class ResetPasswordController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Password Reset Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling password reset requests
    | and uses a simple trait to include this behavior. You're free to
    | explore this trait and override any methods you wish to tweak.
    |
    */

    use ResetsPasswords;

    /**
     * Where to redirect users after resetting their password.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }
    public function sendEmail(Request $request)
    {
        if(!$this->validEmail($request->email)){
            return $this->failedResponse();
        }
       return $this->send($request->email);
    }

    public function send($email)
    {
        $token=$this->createToken($email);
        Mail::to($email)->send(new ResetPasswordMail($token));
        return $this->successResponse($email);
    }
    public function createToken($email)
    {
        $oldtoken=DB::table('password_resets')->where('email',$email)->first();
        if($oldtoken){
            return $oldtoken->token;
        }
        $token=str_random(60);
        return $this->tokenSave($token,$email);
    }
    public function tokenSave($token,$email)
    {
        DB::table('password_resets')->insert([
            'email'=>$email,
            'token'=>$token,
            'created_at'=>Carbon::now()
        ]);
    }
    public function validEmail($email)
    {
        return !!User::where('email',$email)->first();
    }
    public function successResponse($email)
    {
        return response()->json(
            ['message'=>'Please check your Email inbox.','email'=>$email],200);
    }
    public function failedResponse(){
        return response()->json(
            ['error'=>"Email Does not exist."],404);
    }

    public function resetPassword(Request $request){
        $request->validate([
            "password"=>"required|same:retypepassword"
        ]);
        $tokenData=$this->getEmailUsingToken($request);
        return $tokenData ? $this->changesPassword($request, $tokenData->first()->email) : $this->tokenNotFoundResponse();
        // return response()->json(['data'=>$this->getEmailUsingToken($request)],200);
    }

    public function getEmailUsingToken($request)
    {
        return DB::table('password_resets')->where(['token'=>$request->resetToken]);
    }

    public function changesPassword($request,$email){
        $user= User::whereEmail($email)->first();
        $user->update(['password'=>$request->password]);
        $this->getEmailUsingToken($request)->delete();
        return response()->json(['message'=>'Password Successfully Updated.']);
    }

    public function tokenNotFoundResponse()
    {
        return response()->json(['errors'=>'Invalid Request']);
    }
}
