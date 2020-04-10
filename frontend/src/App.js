import React, { Component } from 'react';
//import logo from './logo.svg';
import './App.css';
import Home from './components/Home'
import Login from './components/Login/Login'
import Insights from './components/Insights/Insights'
import ProtectedRoute from './components/ProtectedRoute'
import PublicRoute from './components/PublicRoute'
import { BrowserRouter, Switch, Route} from 'react-router-dom';
import TopNavbar from './components/TopNavbar'
import ForgotPassword from './components/ForgotPassword/ForgotPassword'
import Logout from './components/Logout/Logout'
import Signup from './components/Signup/Signup'
import VerifyEmail from './components/VerifyEmail/VerifyEmail'
import SidebarLayout from './components/SidebarLayout/SidebarLayout';
import ProfileSettings from './components/ProfileSettings/ProfileSettings'
import AgentSettings from './components/AgentSettings/AgentSettings'
import ScannerReports from './components/ScannerReports/ScannerReports'
import ExploitationReports from './components/ExploitationReports/ExploitationReports'
import PostExploitationReports from './components/PostExploitationReports/PostExploitationReports'
class App extends Component {
  render() {
    return (
      <>
      <TopNavbar />
      <BrowserRouter>
      <Switch>
        <Route exact path='/' component={Home} />
        <PublicRoute exact path='/login' component={Login} />
        <PublicRoute exact path='/signup' component={Signup} />
        <PublicRoute exact path='/forgotpassword' component={ForgotPassword} />
        <ProtectedRoute exact path='/dashboard'  render={ (props) => <SidebarLayout {...props} component={<Insights />} /> } />
        <ProtectedRoute exact path='/reports/scanner'  render={ (props) => <SidebarLayout {...props} component={<ScannerReports />} /> } />
        <ProtectedRoute exact path='/reports/exploitation'  render={ (props) => <SidebarLayout {...props} component={<ExploitationReports />} /> } />
        <ProtectedRoute exact path='/reports/postexploitation'  render={ (props) => <SidebarLayout {...props} component={<PostExploitationReports />} /> } />
        <ProtectedRoute exact path='/settings/profile'  render={ (props) => <SidebarLayout {...props} component={<ProfileSettings />} /> } />
        <ProtectedRoute exact path='/settings/agent'  render={ (props) => <SidebarLayout {...props} component={<AgentSettings />} /> } />
        <ProtectedRoute exact path='/logout' component={Logout} />
        <ProtectedRoute exact path='/verifyemail' component={VerifyEmail} />
        
      </Switch>
      </BrowserRouter>
      </>
    )
  }


}

export default App;
