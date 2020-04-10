import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import { Container, NavItem, Nav, Col, Row, NavLink } from 'reactstrap'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faChartBar, faNetworkWired, faShieldAlt, faExclamationTriangle, faBug, faSkullCrossbones, faLaptop, faUserCircle, faScrewdriver } from '@fortawesome/free-solid-svg-icons'
import "./SidebarLayout.css"

class SidebarLayout extends Component {
    constructor(props) {
        super(props)
        this.state= {}
    }

    render() {
        return (<Container fluid={true}>
            <Row> 
                <Col md="2" className="sidebar bg-light">
                    <Nav>
                        <div className="sidebar-sticky">

                            <Nav vertical>
                                <NavItem>
                                    <NavLink tag={Link} to="/dashboard"><FontAwesomeIcon icon={faChartBar}></FontAwesomeIcon> Insights</NavLink>
                                </NavItem>
                            </Nav>
                            <h6 className="sidebar-heading d-flex justify-content-between align-items-center px-3 mt-4 mb-1 text-muted"><span>Reports</span></h6>
                            <Nav vertical>
                                <NavItem>
                                    <NavLink tag={Link} to="/reports/scanner"><FontAwesomeIcon icon={faNetworkWired}></FontAwesomeIcon> Network Scanner</NavLink>
                                </NavItem>
                                <NavItem>
                                    <NavLink tag={Link} to="/reports/exploitation"><FontAwesomeIcon icon={faShieldAlt}></FontAwesomeIcon> Exploitation</NavLink>
                                </NavItem>
                                <NavItem>
                                    <NavLink tag={Link} to="/reports/postexploitation"><FontAwesomeIcon icon={faExclamationTriangle}></FontAwesomeIcon> Post-Exploitation</NavLink>
                                </NavItem>
                                <NavItem>
                                    <NavLink tag={Link} to="/reports/misconfigurations"><FontAwesomeIcon icon={ faScrewdriver }></FontAwesomeIcon> Misconfiguration</NavLink>
                                </NavItem>
                            </Nav>
                            <h6 className="sidebar-heading d-flex justify-content-between align-items-center px-3 mt-4 mb-1 text-muted"><span>Explore</span></h6>
                            <Nav vertical>
                                <NavItem>
                                    <NavLink tag={Link} to="/explore/cves"><FontAwesomeIcon icon={ faBug }></FontAwesomeIcon> CVEs</NavLink>
                                </NavItem>
                                <NavItem>
                                    <NavLink tag={Link} to="/explore/exploits"><FontAwesomeIcon icon={faSkullCrossbones}></FontAwesomeIcon> Exploits</NavLink>
                                </NavItem>
                            </Nav>
                            <h6 className="sidebar-heading d-flex justify-content-between align-items-center px-3 mt-4 mb-1 text-muted"><span>Settings</span></h6>
                            <Nav vertical>
                                <NavItem>
                                    <NavLink tag={Link} to="/settings/agent"><FontAwesomeIcon icon={ faLaptop }></FontAwesomeIcon> Local Agent</NavLink>
                                </NavItem>
                                <NavItem>
                                    <NavLink tag={Link} to="/settings/profile"><FontAwesomeIcon icon={ faUserCircle }></FontAwesomeIcon> Profile</NavLink>
                                </NavItem>
                            </Nav>
                        </div>
                    </Nav>
                </Col>
                <Col role="main" md="9" lg="10" className="border-top py-4">
                    {this.props.component}
                </Col>
            </Row>
        </Container>)
    }
}

export default SidebarLayout;