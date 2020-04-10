import React, { Component } from 'react'
import { Nav, Navbar, NavbarBrand, NavbarToggler, NavItem, NavLink, Collapse } from 'reactstrap'
import Config from '../config'
import API from '../api'
import {faUserTie, faUser, faUserPlus, faInfoCircle, faSignOutAlt, faTachometerAlt} from '@fortawesome/free-solid-svg-icons'
import {FontAwesomeIcon} from '@fortawesome/react-fontawesome'
import {faGithub} from '@fortawesome/free-brands-svg-icons'

class TopNavbar extends Component {
    constructor(props) {
        super(props)
        this.state = { isOpen: false, isLoggedIn: false, user: null }
    }

    async componentDidMount() {
        this.setState({isLoggedIn: await API.checkLoggedIn()})
        if (this.state.isLoggedIn) {
            this.setState({user: await API.getUserInfo()})
        }
    }

    toggle = () => {
        this.setState({ isOpen: !this.state.isOpen })
    }
    render() {
        
        var login = (!this.state.isLoggedIn) ? (<Nav navbar>
            <NavItem>
                <NavLink href="/login"><FontAwesomeIcon icon={faUserTie}></FontAwesomeIcon> Login</NavLink>
            </NavItem>
            <NavItem>
                <NavLink href="/signup"><FontAwesomeIcon icon={faUserPlus}></FontAwesomeIcon> Signup</NavLink>
            </NavItem>
        </Nav>) : null;

        var dashboardLink = (this.state.isLoggedIn && this.state.user) ? (
            <NavItem>
        <NavLink href="/dashboard"><FontAwesomeIcon icon={faTachometerAlt}></FontAwesomeIcon> Dashboard</NavLink>
            </NavItem>
        ) : null;

        var usermenu = (this.state.isLoggedIn && this.state.user) ? (
            <Nav navbar>
            <NavItem>
        <NavLink href="/settings/profile"><FontAwesomeIcon icon={faUser}></FontAwesomeIcon> {this.state.user.username}</NavLink>
            </NavItem>
            <NavItem>
                <NavLink href="/logout"><FontAwesomeIcon icon={faSignOutAlt}></FontAwesomeIcon> Logout</NavLink>
            </NavItem>
            
            </Nav>
        ) : null;

        return <><Navbar color="light" fixed={'top'} light expand="md">
            <NavbarBrand href="/">{Config.brandText}</NavbarBrand>
            <NavbarToggler onClick={this.toggle} />
            <Collapse isOpen={this.state.isOpen} navbar>
                <Nav className="mr-auto" navbar>
                    {dashboardLink}
                    <NavItem>
                        <NavLink href="/about"><FontAwesomeIcon icon={faInfoCircle}></FontAwesomeIcon> About</NavLink>
                    </NavItem>
                    <NavItem>
                        <NavLink href="https://github.com/cstayyab/offensive-mamba" target="_blank"><FontAwesomeIcon icon={faGithub}></FontAwesomeIcon> View On GitHub</NavLink>
                    </NavItem>
                </Nav>
                {(!this.state.isLoggedIn) ? login : usermenu}
            </Collapse>
        </Navbar></>
    }
}

export default TopNavbar